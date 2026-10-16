using System.Diagnostics.Metrics;
using System.Text.Json;
using Sikkerheit.Host.Agents;

namespace Sikkerheit.UnitTests.Agents;

/// <summary>RB-08: the stop criteria of the rings are measured by check-in metrics, with the version of the agent as a tag.</summary>
public sealed class AgentMetricsTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 3, 12, 0, 0, TimeSpan.Zero);

    private static JsonElement Body(string? lastCrashAt, int workingSetMb = 90, int cpuSeconds = 12) => JsonDocument.Parse($$"""
        {"agentVersion":"0.3.1","queueDepth":0,"droppedBatchCount":0,"rejectedBatchCount":0,"serviceStarts":1,"abandonedCollectors":0,
         "configRejected":false,"workingSetMb":{{workingSetMb}},"cpuSeconds":{{cpuSeconds}},"lastCrashAt":{{(lastCrashAt is null ? "null" : $"\"{lastCrashAt}\"")}}}
        """).RootElement;

    private static Dictionary<string, List<(long Value, string? Version)>> Record(Action action)
    {
        var seen = new Dictionary<string, List<(long, string?)>>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == AgentMetrics.MeterName)
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
        {
            string? version = null;
            foreach (var tag in tags)
            {
                if (tag.Key == "agentVersion")
                {
                    version = tag.Value as string;
                }
            }
            if (!seen.TryGetValue(instrument.Name, out var list))
            {
                seen[instrument.Name] = list = [];
            }
            list.Add((value, version));
        });
        listener.Start();
        action();
        return seen;
    }

    [Fact]
    public void Check_in_reports_the_budget_metrics_by_agent_version()
    {
        var seen = Record(() => AgentMetrics.CheckIn(Guid.NewGuid(), Guid.NewGuid(), Body(null, workingSetMb: 140, cpuSeconds: 33), false, Now));
        Assert.Equal([(140L, "0.3.1")], seen["agent.working_set_mb"]);
        Assert.Equal([(33L, "0.3.1")], seen["agent.cpu_seconds"]);
        Assert.False(seen.ContainsKey("agent.recent_crashes"));
    }

    [Theory]
    [InlineData("2026-11-03T09:00:00Z", true)]
    [InlineData("2026-11-01T09:00:00Z", false)]
    public void A_fresh_crash_counts_and_an_old_one_does_not(string crashedAt, bool counted)
    {
        var seen = Record(() => AgentMetrics.CheckIn(Guid.NewGuid(), Guid.NewGuid(), Body(crashedAt), false, Now));
        Assert.Equal(counted, seen.ContainsKey("agent.recent_crashes"));
    }
}
