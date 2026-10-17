using System.Threading.Channels;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.IntegrationTests;

public sealed class JobConcurrencyTests(PostgresFixture postgres) : IAsyncLifetime
{
    private NpgsqlDataSource _source = null!;
    private DbScopes _scopes = null!;
    private readonly TestClock _clock = new();
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public async ValueTask InitializeAsync()
    {
        _source = NpgsqlDataSource.Create(await postgres.CreateDatabaseAsync());
        _scopes = new DbScopes(_source);
    }

    public async ValueTask DisposeAsync() => await _source.DisposeAsync();

    private JobRunner Runner(IEnumerable<IJobHandler> handlers, int collections = 2, int maintenance = 1,
        TimeProvider? clock = null) => new(_scopes, handlers, clock ?? _clock, NullLogger<JobRunner>.Instance,
        new JobExecutionOptions { CollectionConcurrency = collections, MaintenanceConcurrency = maintenance });

    private async Task EnqueueAsync(string type, Guid? org = null)
    {
        await using var scope = await _scopes.PlatformAsync(Ct);
        await JobQueue.EnqueueAsync(scope, type, org, null, Guid.NewGuid().ToString(), _clock.GetUtcNow(), Ct);
        await scope.CommitAsync(Ct);
    }

    [Fact]
    public async Task Two_instances_share_the_collection_limit_and_execute_each_job_once()
    {
        var handler = new BlockingHandler("m365_collect", _scopes);
        for (var i = 0; i < 6; i++) { await EnqueueAsync(handler.Type, Guid.NewGuid()); }
        using var first = Runner([handler]);
        using var second = Runner([handler]);
        var work = new[] { first.RunOnceAsync(Ct), second.RunOnceAsync(Ct) };
        var leases = new[] { await handler.NextAsync(), await handler.NextAsync() };
        try
        {
            var rejected = await Task.WhenAll(Enumerable.Range(0, 8).Select(i => (i % 2 == 0 ? first : second).RunOnceAsync(Ct)));
            Assert.All(rejected, accepted => Assert.False(accepted));
            Assert.Equal(2, leases.Select(l => l.JobId).Distinct().Count());
            await using var scope = await _scopes.PlatformAsync(Ct);
            await using var count = new NpgsqlCommand("select count(*) from job where state = 'running'", scope.Connection, scope.Transaction);
            Assert.Equal(2L, await count.ExecuteScalarAsync(Ct));
        }
        finally { handler.Release(); }
        Assert.All(await Task.WhenAll(work), accepted => Assert.True(accepted));
    }

    [Fact]
    public async Task Two_collection_jobs_for_one_organization_never_run_together()
    {
        var org = Guid.NewGuid();
        var handler = new BlockingHandler("m365_collect", _scopes);
        await EnqueueAsync(handler.Type, org);
        await EnqueueAsync(handler.Type, org);
        await EnqueueAsync(handler.Type, Guid.NewGuid());
        using var runner = Runner([handler], collections: 3);
        var first = runner.RunOnceAsync(Ct);
        var second = runner.RunOnceAsync(Ct);
        var leases = new[] { await handler.NextAsync(), await handler.NextAsync() };
        try
        {
            Assert.Equal(2, leases.Select(l => l.OrganizationId).Distinct().Count());
            Assert.False(await runner.RunOnceAsync(Ct));
        }
        finally { handler.Release(); }
        await Task.WhenAll(first, second);
        Assert.True(await runner.RunOnceAsync(Ct));
    }

    [Fact]
    public async Task Hosted_maintenance_runs_while_all_collection_workers_are_busy()
    {
        var collection = new BlockingHandler("m365_collect", _scopes);
        var report = new BlockingHandler("report_generate", _scopes);
        await EnqueueAsync(collection.Type, Guid.NewGuid());
        await EnqueueAsync(collection.Type, Guid.NewGuid());
        await EnqueueAsync(report.Type, Guid.NewGuid());
        using var runner = Runner([collection, report]);
        await runner.StartAsync(Ct);
        try
        {
            await collection.NextAsync();
            await collection.NextAsync();
            Assert.Equal(report.Type, (await report.NextAsync()).Type);
        }
        finally
        {
            collection.Release();
            report.Release();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await runner.StopAsync(timeout.Token);
        }
    }

    [Fact]
    public async Task Failure_of_one_handler_does_not_cancel_the_other_lane()
    {
        var broken = new FailingHandler();
        var report = new BlockingHandler("report_generate", _scopes);
        report.Release();
        await EnqueueAsync(broken.Type, Guid.NewGuid());
        await EnqueueAsync(report.Type, Guid.NewGuid());
        using var runner = Runner([broken, report]);
        Assert.All(await Task.WhenAll(runner.RunOnceAsync(Ct), runner.RunOnceAsync(Ct)), accepted => Assert.True(accepted));
        await using var scope = await _scopes.PlatformAsync(Ct);
        await using var read = new NpgsqlCommand("select type, state, attempts from job", scope.Connection, scope.Transaction);
        await using var reader = await read.ExecuteReaderAsync(Ct);
        var states = new Dictionary<string, (string State, int Attempts)>();
        while (await reader.ReadAsync(Ct)) { states[reader.GetString(0)] = (reader.GetString(1), reader.GetInt32(2)); }
        Assert.Equal(("queued", 1), states[broken.Type]);
        Assert.Equal(("succeeded", 1), states[report.Type]);
    }

    [Fact]
    public async Task Expired_lease_can_be_reclaimed_at_capacity_and_old_effects_are_fenced()
    {
        await EnqueueAsync("m365_collect", Guid.NewGuid());
        var options = new JobExecutionOptions { CollectionConcurrency = 1 };
        var first = await JobClaims.CaptureAsync(_scopes, _clock, "first", options, true, Ct);
        Assert.NotNull(first);
        Assert.Null(await JobClaims.CaptureAsync(_scopes, _clock, "second", options, true, Ct));
        _clock.Set(_clock.GetUtcNow().AddMinutes(6));
        var next = await JobClaims.CaptureAsync(_scopes, _clock, "second", options, true, Ct);
        Assert.NotNull(next);
        Assert.Equal(first.JobId, next.JobId);
        Assert.Equal(first.Token + 1, next.Token);
        await using var scope = await _scopes.PlatformAsync(Ct);
        Assert.False(await first.HoldAsync(scope, Ct));
        await Assert.ThrowsAsync<JobLeaseLostException>(() => first.CompleteAsync(scope, Ct));
    }

    [Fact]
    public async Task Losing_the_lease_cancels_the_inflight_handler_without_overwriting_the_new_owner()
    {
        var handler = new BlockingHandler("m365_collect", _scopes);
        await EnqueueAsync(handler.Type, Guid.NewGuid());
        using var runner = Runner([handler], clock: new FastRenewalClock());
        var work = runner.RunOnceAsync(Ct);
        var lease = await handler.NextAsync();
        await using (var scope = await _scopes.PlatformAsync(Ct))
        {
            await using var takeover = new NpgsqlCommand("update job set lease_token = lease_token + 1, lease_owner = 'new-owner' where id = @id",
                scope.Connection, scope.Transaction);
            takeover.Parameters.AddWithValue("id", lease.JobId);
            await takeover.ExecuteNonQueryAsync(Ct);
            await scope.CommitAsync(Ct);
        }
        Assert.True(await work.WaitAsync(TimeSpan.FromSeconds(5), Ct));
        await using var check = await _scopes.PlatformAsync(Ct);
        await using var read = new NpgsqlCommand("select state, lease_owner from job where id = @id", check.Connection, check.Transaction);
        read.Parameters.AddWithValue("id", lease.JobId);
        await using var reader = await read.ExecuteReaderAsync(Ct);
        Assert.True(await reader.ReadAsync(Ct));
        Assert.Equal("running", reader.GetString(0));
        Assert.Equal("new-owner", reader.GetString(1));
    }

    [Fact]
    public async Task Backlog_snapshot_excludes_future_and_active_jobs_but_includes_expired_leases()
    {
        await EnqueueAsync("m365_collect", Guid.NewGuid());
        await using (var scope = await _scopes.PlatformAsync(Ct))
        {
            await JobQueue.EnqueueAsync(scope, "report_generate", Guid.NewGuid(), null, "future", _clock.GetUtcNow().AddDays(1), Ct);
            await scope.CommitAsync(Ct);
        }
        var before = await JobMonitor.ReadAsync(_scopes, _clock.GetUtcNow(), Ct);
        Assert.Equal(1, before.Single(lane => lane.Lane == "collection").Ready);
        Assert.Equal(0, before.Single(lane => lane.Lane == "maintenance").Ready);
        Assert.NotNull(await JobClaims.CaptureAsync(_scopes, _clock, "first", new(), true, Ct));
        Assert.All(await JobMonitor.ReadAsync(_scopes, _clock.GetUtcNow(), Ct), lane => Assert.Equal(0, lane.Ready));
        _clock.Set(_clock.GetUtcNow().AddMinutes(6));
        var expired = (await JobMonitor.ReadAsync(_scopes, _clock.GetUtcNow(), Ct)).Single(lane => lane.Lane == "collection");
        Assert.Equal(1, expired.Ready);
        Assert.True(expired.OldestReadySeconds >= 360);
    }

    private sealed class BlockingHandler(string type, DbScopes scopes) : IJobHandler
    {
        private readonly Channel<JobLease> _entered = Channel.CreateUnbounded<JobLease>();
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public string Type => type;
        public Task<JobLease> NextAsync() => _entered.Reader.ReadAsync(Ct).AsTask().WaitAsync(TimeSpan.FromSeconds(5), Ct);
        public void Release() => _release.TrySetResult();

        public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
        {
            await _entered.Writer.WriteAsync(lease, ct);
            await _release.Task.WaitAsync(ct);
            await using var scope = await scopes.PlatformAsync(ct);
            Assert.True(await lease.HoldAsync(scope, ct));
            await lease.CompleteAsync(scope, ct);
            await scope.CommitAsync(ct);
        }
    }

    private sealed class FailingHandler : IJobHandler
    {
        public string Type => "m365_collect";
        public Task ExecuteAsync(JobLease lease, CancellationToken ct) => throw new InvalidOperationException("synthetic failure");
    }

    private sealed class FastRenewalClock : TimeProvider
    {
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            System.CreateTimer(callback, state, dueTime == TimeSpan.FromMinutes(1) ? TimeSpan.FromMilliseconds(50) : dueTime, period);
    }
}
