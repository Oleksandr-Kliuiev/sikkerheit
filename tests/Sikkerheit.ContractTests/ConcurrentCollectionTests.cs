using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Sikkerheit.ContractTests.Support;
using Sikkerheit.Host.Jobs;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests;

public sealed class ConcurrentCollectionTests(PostgresFixture postgres)
{
    [Fact]
    public async Task A_scheduled_job_blocked_by_a_manual_collection_joins_its_completed_result()
    {
        await using var host = await ContractHost.StartAsync(postgres);
        var tenant = host.Tenant();
        tenant.SecurityDefaults = true;
        var org = await host.OrganizationAsync();
        await host.ConnectAsync(org, tenant);
        host.Graph.Requests.Clear();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var ct = TestContext.Current.CancellationToken;
        host.Graph.OnRequest = async path =>
        {
            if (path == "/users") { entered.TrySetResult(); await release.Task.WaitAsync(ct); }
        };
        var first = host.Factory.Services.GetRequiredService<JobRunner>();
        using var second = new JobRunner(host.Scopes, host.Factory.Services.GetServices<IJobHandler>(), host.Clock, NullLogger<JobRunner>.Instance);
        var collecting = first.RunOnceAsync(ct);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), ct);
        try
        {
            await using var scope = await host.Scopes.PlatformAsync(ct);
            await JobQueue.EnqueueAsync(scope, "m365_collect", org, null, "scheduled-overlap", host.Clock.GetUtcNow(), ct);
            await scope.CommitAsync(ct);
            Assert.False(await second.RunOnceAsync(ct));
        }
        finally { release.TrySetResult(); }
        Assert.True(await collecting);
        Assert.True(await second.RunOnceAsync(ct));
        Assert.Equal(1, host.Graph.Requests.Count(path => path.StartsWith("GET /v1.0/organization?", StringComparison.Ordinal)));
        var runs = await host.Admin.GetAsync($"/api/v1/organizations/{org}/collection-runs", "CollectionRunPage");
        Assert.Single(runs.Body.GetProperty("items").EnumerateArray());
    }
}
