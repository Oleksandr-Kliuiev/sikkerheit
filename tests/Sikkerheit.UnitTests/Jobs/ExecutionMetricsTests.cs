using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.M365;

namespace Sikkerheit.UnitTests.Jobs;

public sealed class ExecutionMetricsTests
{
    [Fact]
    public void Execution_metrics_expose_only_bounded_labels_without_tenants_users_or_paths()
    {
        var seen = new ConcurrentBag<(string Name, string[] Keys)>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, owner) =>
        {
            if (instrument.Meter.Name is JobMetrics.MeterName or GraphMetrics.MeterName)
            {
                owner.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, _, tags, _) => seen.Add((instrument.Name, tags.ToArray().Select(tag => tag.Key).ToArray())));
        listener.SetMeasurementEventCallback<double>((instrument, _, tags, _) => seen.Add((instrument.Name, tags.ToArray().Select(tag => tag.Key).ToArray())));
        listener.Start();
        JobMetrics.Queued("m365_collect", TimeSpan.FromSeconds(30));
        JobMetrics.Started("m365_collect");
        JobMetrics.Finished("m365_collect", "completed", TimeSpan.FromSeconds(1));
        JobMetrics.PublishQueue([new("collection", 3, 60), new("maintenance", 0, 0)]);
        GraphMetrics.Wait(GraphLimit.AuthMethods, TimeSpan.FromMinutes(10));
        GraphMetrics.Response(GraphLimit.AuthMethods, 429, "request");
        listener.RecordObservableInstruments();
        Assert.Contains(seen, item => item.Name == "sikkerheit.jobs.oldest_ready_age");
        Assert.Contains(seen, item => item.Name == "sikkerheit.graph.responses");
        Assert.All(seen, item => Assert.All(item.Keys, key => Assert.Contains(key, new[] { "lane", "outcome", "limit", "status", "kind" })));
    }
}
