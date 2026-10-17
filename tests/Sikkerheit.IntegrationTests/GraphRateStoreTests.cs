using Npgsql;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.M365;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.IntegrationTests;

public sealed class GraphRateStoreTests(PostgresFixture postgres) : IAsyncLifetime
{
    private NpgsqlDataSource _source = null!;
    private DbScopes _scopes = null!;
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public async ValueTask InitializeAsync()
    {
        _source = NpgsqlDataSource.Create(await postgres.CreateDatabaseAsync());
        _scopes = new DbScopes(_source);
    }

    public async ValueTask DisposeAsync() => await _source.DisposeAsync();

    [Fact]
    public async Task Independent_instances_cannot_exceed_the_same_tenant_window()
    {
        var tenant = Guid.NewGuid();
        var stores = new[] { new PostgresGraphRateStore(_scopes), new PostgresGraphRateStore(new DbScopes(_source)) };
        var results = await Task.WhenAll(Enumerable.Range(0, 12)
            .Select(i => stores[i % 2].TryAcquireAsync(GraphLimit.AuthMethods, tenant, 1, Ct)));
        Assert.Equal(5, results.Count(delay => delay == TimeSpan.Zero));
        Assert.All(results.Where(delay => delay > TimeSpan.Zero), delay => Assert.InRange(delay.TotalSeconds, 0, 10));
    }

    [Fact]
    public async Task A_rejected_batch_consumes_no_partial_quota()
    {
        var tenant = Guid.NewGuid();
        var store = new PostgresGraphRateStore(_scopes);
        Assert.Equal(TimeSpan.Zero, await store.TryAcquireAsync(GraphLimit.AuthMethods, tenant, 4, Ct));
        Assert.True(await store.TryAcquireAsync(GraphLimit.AuthMethods, tenant, 2, Ct) > TimeSpan.Zero);
        Assert.Equal(TimeSpan.Zero, await store.TryAcquireAsync(GraphLimit.AuthMethods, tenant, 1, Ct));
        Assert.True(await store.TryAcquireAsync(GraphLimit.AuthMethods, tenant, 1, Ct) > TimeSpan.Zero);
    }

    [Fact]
    public async Task Global_quota_is_shared_across_tenants_and_instances()
    {
        var results = await Task.WhenAll(Enumerable.Range(0, 30).Select(_ => new PostgresGraphRateStore(new DbScopes(_source))
            .TryAcquireAsync(GraphLimit.AuthMethods, Guid.NewGuid(), 5, Ct)));
        Assert.Equal(24, results.Count(delay => delay == TimeSpan.Zero)); // 120 of 122 places reserved.
        var store = new PostgresGraphRateStore(_scopes);
        Assert.Equal(TimeSpan.Zero, await store.TryAcquireAsync(GraphLimit.AuthMethods, Guid.NewGuid(), 2, Ct));
        Assert.True(await store.TryAcquireAsync(GraphLimit.AuthMethods, Guid.NewGuid(), 1, Ct) > TimeSpan.Zero);
    }

    [Fact]
    public async Task Cooldown_survives_a_new_instance_and_a_shorter_delay_cannot_clear_it()
    {
        var tenant = Guid.NewGuid();
        var store = new PostgresGraphRateStore(_scopes);
        await store.DeferAsync(GraphLimit.AuthMethods, tenant, TimeSpan.FromMinutes(10), Ct);
        var restarted = new PostgresGraphRateStore(new DbScopes(_source));
        await restarted.DeferAsync(GraphLimit.AuthMethods, tenant, TimeSpan.FromSeconds(1), Ct);
        var wait = await restarted.TryAcquireAsync(GraphLimit.AuthMethods, tenant, 1, Ct);
        Assert.InRange(wait.TotalSeconds, 590, 600);
        Assert.InRange((await restarted.TryAcquireAsync(GraphLimit.Default, tenant, 1, Ct)).TotalSeconds, 590, 600);
        Assert.True(await restarted.TryAcquireAsync(GraphLimit.AuthMethods, Guid.NewGuid(), 1, Ct) > TimeSpan.Zero);
        Assert.Equal(TimeSpan.Zero, await restarted.TryAcquireAsync(GraphLimit.Default, Guid.NewGuid(), 1, Ct));
    }

    [Fact]
    public async Task Expired_windows_are_reclaimed_and_operational_rows_are_removed()
    {
        var tenant = Guid.NewGuid();
        var store = new PostgresGraphRateStore(_scopes);
        Assert.Equal(TimeSpan.Zero, await store.TryAcquireAsync(GraphLimit.AuthMethods, tenant, 5, Ct));
        await using (var connection = await _source.OpenConnectionAsync(Ct))
        await using (var expire = new NpgsqlCommand("update graph_rate_window set expires_at = now() - interval '1 second'", connection))
        {
            await expire.ExecuteNonQueryAsync(Ct);
        }
        Assert.Equal(TimeSpan.Zero, await store.TryAcquireAsync(GraphLimit.Default, Guid.NewGuid(), 1, Ct));
        await using var scope = await _scopes.PlatformAsync(Ct);
        await using var count = new NpgsqlCommand("select count(*) from graph_rate_window", scope.Connection, scope.Transaction);
        Assert.Equal(1L, await count.ExecuteScalarAsync(Ct));
    }

    [Fact]
    public async Task Long_server_cooldowns_do_not_overflow_database_timestamps()
    {
        var tenant = Guid.NewGuid();
        var store = new PostgresGraphRateStore(_scopes);
        await store.DeferAsync(GraphLimit.Default, tenant, TimeSpan.MaxValue, Ct);
        var wait = await store.TryAcquireAsync(GraphLimit.Default, tenant, 1, Ct);
        Assert.True(wait > TimeSpan.FromDays(365));
    }

    [Fact]
    public async Task Cancellation_never_grants_a_quota()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new PostgresGraphRateStore(_scopes)
            .TryAcquireAsync(GraphLimit.AuthMethods, Guid.NewGuid(), 1, cancelled.Token));
    }
}
