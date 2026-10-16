using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Text.Json;

namespace Sikkerheit.Host.Agents;

/// <summary>
/// Metrics of the agent API for Application Insights (06 «Наблюдаемость и оповещения»): check-in telemetry by device, agent
/// version and organization, and the outcome of every batch. The alerts, the stop criteria of the rings (RB-08) and the analysis
/// of RB-12 work from them. No body, token or key is a tag.
/// </summary>
public static class AgentMetrics
{
    public const string MeterName = "Sikkerheit.Agents";
    private static readonly Meter Meter = new(MeterName);

    private static readonly Counter<long> CheckIns = Meter.CreateCounter<long>("agent.check_ins");
    private static readonly Histogram<long> QueueDepth = Meter.CreateHistogram<long>("agent.queue_depth");
    private static readonly Counter<long> DroppedBatches = Meter.CreateCounter<long>("agent.dropped_batches");
    private static readonly Counter<long> RejectedBatches = Meter.CreateCounter<long>("agent.rejected_batches");
    private static readonly Counter<long> ConfigRejected = Meter.CreateCounter<long>("agent.config_rejected");
    private static readonly Counter<long> ServiceStarts = Meter.CreateCounter<long>("agent.service_starts");
    private static readonly Counter<long> AbandonedCollectors = Meter.CreateCounter<long>("agent.abandoned_collectors");
    private static readonly Counter<long> ClockInconsistent = Meter.CreateCounter<long>("agent.clock_inconsistent");
    private static readonly Counter<long> Batches = Meter.CreateCounter<long>("agent.batches");
    private static readonly Histogram<double> ScanSeconds = Meter.CreateHistogram<double>("agent.submit_scan.seconds", "s");

    private static TagList Tags(Guid organizationId, Guid deviceId, string? version) => new()
    {
        { "organizationId", organizationId.ToString() }, { "deviceId", deviceId.ToString() }, { "agentVersion", version ?? "unknown" },
    };

    public static void CheckIn(Guid organizationId, Guid deviceId, JsonElement body, bool clockInconsistent)
    {
        var tags = Tags(organizationId, deviceId, body.GetProperty("agentVersion").GetString());
        CheckIns.Add(1, tags);
        QueueDepth.Record(body.GetProperty("queueDepth").GetInt64(), tags);
        DroppedBatches.Add(body.GetProperty("droppedBatchCount").GetInt64(), tags);
        RejectedBatches.Add(body.GetProperty("rejectedBatchCount").GetInt64(), tags);
        ServiceStarts.Add(body.GetProperty("serviceStarts").GetInt64(), tags);
        AbandonedCollectors.Add(body.GetProperty("abandonedCollectors").GetInt64(), tags);
        if (body.GetProperty("configRejected").GetBoolean())
        {
            ConfigRejected.Add(1, tags);
        }
        if (clockInconsistent)
        {
            ClockInconsistent.Add(1, tags);
        }
    }

    /// <summary>The outcome of a batch: accepted, duplicate or the Problem code that refused it (422 per device and code).</summary>
    public static void Batch(Guid organizationId, Guid deviceId, string outcome, TimeSpan duration)
    {
        var tags = Tags(organizationId, deviceId, null);
        tags.Add("outcome", outcome);
        Batches.Add(1, tags);
        ScanSeconds.Record(duration.TotalSeconds, tags);
    }
}
