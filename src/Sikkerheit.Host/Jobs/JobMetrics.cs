using System.Diagnostics.Metrics;

namespace Sikkerheit.Host.Jobs;

public static class JobMetrics
{
    public const string MeterName = "Sikkerheit.Jobs";
    private static readonly Meter Meter = new(MeterName);
    private static readonly UpDownCounter<long> Active = Meter.CreateUpDownCounter<long>("sikkerheit.jobs.active");
    private static readonly Histogram<double> QueueWait = Meter.CreateHistogram<double>("sikkerheit.jobs.queue_wait", "s");
    private static readonly Histogram<double> Duration = Meter.CreateHistogram<double>("sikkerheit.jobs.duration", "s");
    private static readonly Counter<long> Outcomes = Meter.CreateCounter<long>("sikkerheit.jobs.executions");
    private static JobLaneSnapshot[] _queue = [];

    static JobMetrics()
    {
        Meter.CreateObservableGauge<long>("sikkerheit.jobs.ready", () => Volatile.Read(ref _queue)
            .Select(value => new Measurement<long>(value.Ready, new KeyValuePair<string, object?>("lane", value.Lane))));
        Meter.CreateObservableGauge<double>("sikkerheit.jobs.oldest_ready_age", () => Volatile.Read(ref _queue)
            .Select(value => new Measurement<double>(value.OldestReadySeconds,
                new KeyValuePair<string, object?>("lane", value.Lane))), "s");
    }

    public static void PublishQueue(IReadOnlyList<JobLaneSnapshot> snapshot) => Volatile.Write(ref _queue, snapshot.ToArray());

    private static string Lane(string type) => type == "m365_collect" ? "collection" : "maintenance";

    public static void Queued(string type, TimeSpan wait) =>
        QueueWait.Record(Math.Max(0, wait.TotalSeconds), new KeyValuePair<string, object?>("lane", Lane(type)));

    public static void Started(string type) => Active.Add(1, new KeyValuePair<string, object?>("lane", Lane(type)));

    public static void Finished(string type, string outcome, TimeSpan duration)
    {
        var lane = new KeyValuePair<string, object?>("lane", Lane(type));
        Active.Add(-1, lane);
        Duration.Record(duration.TotalSeconds, lane);
        Outcomes.Add(1, lane, new KeyValuePair<string, object?>("outcome", outcome));
    }
}
