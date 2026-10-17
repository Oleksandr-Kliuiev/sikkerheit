using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.IntegrationTests;

/// <summary>Opt-in queue profile on real PostgreSQL. Synthetic handlers, no Graph or Windows performance claims.</summary>
public sealed class JobCapacityTests(PostgresFixture postgres)
{
    public static bool Enabled => Environment.GetEnvironmentVariable("SIKKERHEIT_QUEUE_PROFILE") == "1";

    [Fact(SkipUnless = nameof(Enabled), Skip = "Run tools/load/run_queue_profile.py for the isolated capacity profile")]
    public async Task Two_instances_process_100_collection_and_1000_maintenance_jobs_with_shared_bounds()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var source = NpgsqlDataSource.Create(await postgres.CreateDatabaseAsync());
        var scopes = new DbScopes(source);
        var collections = new Probe("m365_collect", scopes, 100);
        var maintenance = new Probe("profile_probe", scopes, 1000);
        var now = DateTimeOffset.UtcNow;
        var organizations = Enumerable.Range(0, 100).Select(_ => Guid.NewGuid()).ToArray();
        await using (var scope = await scopes.PlatformAsync(ct))
        {
            for (var i = 0; i < 1000; i++)
            {
                if (i < 100)
                {
                    await JobQueue.EnqueueAsync(scope, collections.Type, organizations[i], null, "capacity", now, ct);
                }
                await JobQueue.EnqueueAsync(scope, maintenance.Type, organizations[i % 100], null, i.ToString(System.Globalization.CultureInfo.InvariantCulture), now, ct);
            }
            await scope.CommitAsync(ct);
        }
        using var first = new JobRunner(scopes, [collections, maintenance], TimeProvider.System, NullLogger<JobRunner>.Instance);
        using var second = new JobRunner(scopes, [collections, maintenance], TimeProvider.System, NullLogger<JobRunner>.Instance);
        var started = Stopwatch.GetTimestamp();
        await Task.WhenAll(first.StartAsync(ct), second.StartAsync(ct));
        try
        {
            await Task.WhenAll(collections.Done, maintenance.Done).WaitAsync(TimeSpan.FromMinutes(2), ct);
        }
        finally
        {
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await Task.WhenAll(first.StopAsync(stop.Token), second.StopAsync(stop.Token));
        }
        var elapsed = Stopwatch.GetElapsedTime(started);
        Assert.Equal(100, collections.Executed.Count);
        Assert.Equal(1000, maintenance.Executed.Count);
        Assert.InRange(collections.Maximum, 1, 8);
        Assert.InRange(maintenance.Maximum, 1, 2);
        await using (var scope = await scopes.PlatformAsync(ct))
        await using (var count = new NpgsqlCommand("select count(*) from job where state = 'succeeded' and attempts = 1", scope.Connection, scope.Transaction))
        {
            Assert.Equal(1100L, await count.ExecuteScalarAsync(ct));
        }
        var report = new
        {
            status = "passed", measuredAt = DateTimeOffset.UtcNow, profile = "postgres_queue_synthetic_handlers",
            instances = 2, organizations = 100, collectionJobs = 100, maintenanceJobs = 1000,
            elapsedSeconds = elapsed.TotalSeconds, maximumCollectionConcurrency = collections.Maximum,
            maximumMaintenanceConcurrency = maintenance.Maximum, maintenanceWaitP95Seconds = maintenance.WaitP95,
            limitations = new[] { "No real Graph requests", "No agent HTTP/assessment workload", "Not AT-17 or an Azure capacity result" },
        };
        var path = Environment.GetEnvironmentVariable("SIKKERHEIT_QUEUE_PROFILE_REPORT");
        if (!string.IsNullOrEmpty(path))
        {
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }) + "\n", ct);
        }
    }

    private sealed class Probe(string type, DbScopes scopes, int expected) : IJobHandler
    {
        private readonly TaskCompletionSource _done = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly ConcurrentBag<double> _waits = [];
        private int _active;
        private int _maximum;
        private int _completed;
        public string Type => type;
        public ConcurrentDictionary<Guid, byte> Executed { get; } = new();
        public Task Done => _done.Task;
        public int Maximum => Volatile.Read(ref _maximum);
        public double WaitP95 => _waits.Order().ElementAt((int)Math.Ceiling(_waits.Count * .95) - 1);

        public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
        {
            var active = Interlocked.Increment(ref _active);
            int observed;
            do { observed = Maximum; }
            while (active > observed && Interlocked.CompareExchange(ref _maximum, active, observed) != observed);
            try
            {
                Assert.True(Executed.TryAdd(lease.JobId, 0), "a job must not execute twice");
                await Task.Delay(TimeSpan.FromMilliseconds(5), ct);
            }
            finally { Interlocked.Decrement(ref _active); }
            await using var scope = await scopes.PlatformAsync(ct);
            Assert.True(await lease.HoldAsync(scope, ct));
            await using (var age = new NpgsqlCommand("select extract(epoch from (clock_timestamp() - next_attempt_at))::double precision from job where id = @id",
                scope.Connection, scope.Transaction))
            {
                age.Parameters.AddWithValue("id", lease.JobId);
                _waits.Add((double)(await age.ExecuteScalarAsync(ct))!);
            }
            await lease.CompleteAsync(scope, ct);
            await scope.CommitAsync(ct);
            if (Interlocked.Increment(ref _completed) == expected) { _done.TrySetResult(); }
        }
    }
}
