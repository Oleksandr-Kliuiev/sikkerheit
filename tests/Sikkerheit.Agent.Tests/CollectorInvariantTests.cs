using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Sikkerheit.Agent.Collectors;
using Sikkerheit.Agent.Collectors.Runtime;
using Sikkerheit.Contracts;

namespace Sikkerheit.Agent.Tests;

/// <summary>Records enforced by the collectors and their runner; the readers of Windows are replaced with fakes.</summary>
public sealed class CollectorInvariantTests
{
    private static readonly CollectionContext Context = new(AgentFixture.Start, FakeVolume.Os, CancellationToken.None);

    [Fact]
    [Invariant("INV-152")]
    public void Inv152_more_than_ten_antivirus_products_are_unavailable_unsupported_and_not_truncated()
    {
        var products = Enumerable.Range(1, 11).Select(i => new SecurityProductRaw("Vendor " + i, 0x061000)).ToList();
        var collector = new AntivirusCollector(new FakeCenter(products), new FakeDefender(null));

        var outcome = collector.Collect(Context);

        Assert.False(outcome.IsCollected);
        Assert.Equal("unsupported", outcome.ReasonCode);
    }

    [Fact]
    public void Ten_antivirus_products_are_collected_and_validate_by_the_schema()
    {
        var products = Enumerable.Range(1, 10).Select(i => new SecurityProductRaw("Vendor " + i, 0x061000)).ToList();
        var outcome = new AntivirusCollector(new FakeCenter(products), new FakeDefender(null)).Collect(Context);

        Assert.True(outcome.IsCollected);
        Assert.Equal(10, outcome.Evidence!["products"]!.AsArray().Count);
        Assert.Null(outcome.Evidence["defender"]);
    }

    [Fact]
    [Invariant("INV-154")]
    public async Task Inv154_a_temporary_error_of_a_windows_api_is_unavailable_temporary_error_for_that_check_only()
    {
        var collectors = new List<ICollector>
        {
            new BitLockerCollector(new ThrowingBitLocker(new IOException("WMI timeout"))),
            new DiskSpaceCollector(new FixedSpace(256_000_000_000, 18_000_000_000)),
            new SecureBootCollector(new ThrowingSecureBoot(new System.Runtime.InteropServices.COMException("RPC server unavailable"))),
        };

        var items = await new CollectorRunner().RunAsync(collectors, Context, CollectorLimits.Default);

        Assert.Equal("temporary_error", items[0].Outcome.ReasonCode);
        Assert.True(items[1].Outcome.IsCollected);
        Assert.Equal("temporary_error", items[2].Outcome.ReasonCode);
    }

    [Fact]
    public async Task An_access_denied_and_an_unsupported_api_have_their_own_reasons()
    {
        var collectors = new List<ICollector>
        {
            new BitLockerCollector(new ThrowingBitLocker(new UnauthorizedAccessException())),
            new SecureBootCollector(new ThrowingSecureBoot(new PlatformNotSupportedException())),
        };

        var items = await new CollectorRunner().RunAsync(collectors, Context, CollectorLimits.Default);

        Assert.Equal("permission_denied", items[0].Outcome.ReasonCode);
        Assert.Equal("unsupported", items[1].Outcome.ReasonCode);
    }

    [Fact]
    [Invariant("INV-153")]
    public async Task Inv153_a_hung_collector_gets_collector_timeout_the_others_are_kept_and_the_thread_is_counted_as_abandoned()
    {
        using var release = new ManualResetEventSlim();
        var collectors = new List<ICollector>
        {
            new StubCollector("WIN-001", _ => CollectorOutcome.Collected(StubCollectors.Evidence("WIN-001"))),
            new StubCollector("WIN-002", _ =>
            {
                release.Wait(TimeSpan.FromSeconds(30));
                return CollectorOutcome.Collected(StubCollectors.Evidence("WIN-002"));
            }),
            new StubCollector("WIN-009", _ => CollectorOutcome.Collected(StubCollectors.Evidence("WIN-009"))),
        };
        var runner = new CollectorRunner();

        var started = Stopwatch();
        var items = await runner.RunAsync(collectors, Context, new CollectorLimits(TimeSpan.FromMilliseconds(300), TimeSpan.FromSeconds(5)));

        Assert.True(items[0].Outcome.IsCollected);
        Assert.Equal("collector_timeout", items[1].Outcome.ReasonCode);
        Assert.True(items[2].Outcome.IsCollected);
        Assert.Equal(1, runner.AbandonedCount);
        Assert.True(started() < TimeSpan.FromSeconds(3));
        release.Set();
    }

    [Fact]
    [Invariant("INV-153")]
    public async Task Inv153_the_session_limit_gives_collector_timeout_to_the_collectors_that_did_not_finish()
    {
        using var release = new ManualResetEventSlim();
        var collectors = new List<ICollector>
        {
            new StubCollector("WIN-001", _ => CollectorOutcome.Collected(StubCollectors.Evidence("WIN-001"))),
            new StubCollector("WIN-002", _ =>
            {
                release.Wait(TimeSpan.FromSeconds(30));
                return CollectorOutcome.Collected(StubCollectors.Evidence("WIN-002"));
            }),
        };

        // The session limit (200 ms) is shorter than the limit of the collector (30 s).
        var items = await new CollectorRunner().RunAsync(collectors, Context, new CollectorLimits(TimeSpan.FromSeconds(30), TimeSpan.FromMilliseconds(200)));

        Assert.True(items[0].Outcome.IsCollected);
        Assert.Equal("collector_timeout", items[1].Outcome.ReasonCode);
        release.Set();
    }

    [Fact]
    [Invariant("INV-153")]
    public async Task Inv153_three_abandoned_collectors_make_the_service_exit_so_that_scm_restarts_it()
    {
        using var release = new ManualResetEventSlim();
        using var f = new AgentFixture(
            () => [.. StubCollectors.CheckIds.Select(id => id is "WIN-001" or "WIN-002" or "WIN-009"
                ? new StubCollector(id, _ =>
                {
                    release.Wait(TimeSpan.FromSeconds(30));
                    return CollectorOutcome.Unavailable("temporary_error");
                })
                : (ICollector)new StubCollector(id, _ => CollectorOutcome.Collected(StubCollectors.Evidence(id))))],
            new CollectorLimits(TimeSpan.FromMilliseconds(200), TimeSpan.FromSeconds(5)));

        await f.EnrolledAsync();

        Assert.True(f.Engine.ShouldExit);
        var batch = f.Server.Accepted.Single()["observations"]!.AsArray();
        Assert.Equal(3, batch.Count(o => o!["reasonCode"]?.GetValue<string>() == "collector_timeout"));
        Assert.Equal(8, batch.Count(o => o!["collectionStatus"]!.GetValue<string>() == "collected"));
        release.Set();
    }

    [Fact]
    public async Task The_collector_runs_in_its_own_thread_and_a_sta_collector_gets_a_sta_thread_on_windows()
    {
        var threads = new Dictionary<string, (int Id, ApartmentState State)>();
        var collectors = new List<ICollector>
        {
            new StubCollector("WIN-001", _ => Remember(threads, "a")),
            new StubCollector("WIN-005", _ => Remember(threads, "b"), sta: true),
        };

        await new CollectorRunner().RunAsync(collectors, Context, CollectorLimits.Default);

        Assert.NotEqual(Environment.CurrentManagedThreadId, threads["a"].Id);
        Assert.NotEqual(threads["a"].Id, threads["b"].Id);
        if (OperatingSystem.IsWindows())
        {
            Assert.Equal(ApartmentState.STA, threads["b"].State);
        }
    }

    [Fact]
    public async Task Every_observation_of_the_collectors_with_good_readers_validates_by_the_embedded_schema()
    {
        var readers = FakeReaders.Good();
        var items = await new CollectorRunner().RunAsync(CollectorSet.Create(readers), Context, CollectorLimits.Default);

        var schemas = new ContractSchemas();
        Assert.Equal(11, items.Count);
        foreach (var item in items)
        {
            Assert.True(item.Outcome.IsCollected, item.Collector.CheckId + " " + item.Outcome.ReasonCode);
            var subject = Catalog.Check(item.Collector.CheckId).SubjectType == "volume"
                ? new System.Text.Json.Nodes.JsonObject { ["type"] = "volume", ["volumeId"] = FakeVolume.Os.VolumeId, ["mountPoint"] = "C:", ["role"] = "os" }
                : new System.Text.Json.Nodes.JsonObject { ["type"] = "device" };
            var observation = new System.Text.Json.Nodes.JsonObject
            {
                ["checkId"] = item.Collector.CheckId,
                ["collectorVersion"] = item.Collector.CollectorVersion,
                ["subject"] = subject,
                ["observedAt"] = "2026-10-16T08:00:00Z",
                ["collectionStatus"] = "collected",
                ["evidence"] = item.Outcome.Evidence!.DeepClone(),
            };
            using var document = JsonDocument.Parse(observation.ToJsonString());
            Assert.Empty(schemas.ValidateStandalone("observation.schema.json", document.RootElement));
        }
    }

    private static CollectorOutcome Remember(Dictionary<string, (int, ApartmentState)> map, string key)
    {
        lock (map)
        {
            map[key] = (Environment.CurrentManagedThreadId, Thread.CurrentThread.GetApartmentState());
        }
        return CollectorOutcome.Unavailable("unsupported");
    }

    private static Func<TimeSpan> Stopwatch()
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        return () => watch.Elapsed;
    }
}

internal sealed class FakeCenter(IReadOnlyList<SecurityProductRaw> antivirus, IReadOnlyList<SecurityProductRaw>? firewall = null) : ISecurityCenterReader
{
    public IReadOnlyList<SecurityProductRaw> AntivirusProducts() => antivirus;

    public IReadOnlyList<SecurityProductRaw> FirewallProducts() => firewall ?? [];
}

internal sealed class FakeDefender(DefenderRaw? value) : IDefenderReader
{
    public DefenderRaw? Read() => value;
}

internal sealed class FixedSpace(long total, long free) : IVolumeSpaceReader
{
    public VolumeSpace Read(VolumeRef volume) => new(total, free);
}

internal sealed class ThrowingBitLocker(Exception exception) : IBitLockerReader
{
    [DoesNotReturn]
    public BitLockerRaw? Read(VolumeRef volume) => throw exception;
}

internal sealed class ThrowingSecureBoot(Exception exception) : ISecureBootReader
{
    [DoesNotReturn]
    public SecureBootRaw Read() => throw exception;
}
