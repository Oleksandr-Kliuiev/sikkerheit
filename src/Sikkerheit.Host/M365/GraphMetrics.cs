using System.Diagnostics.Metrics;

namespace Sikkerheit.Host.M365;

public static class GraphMetrics
{
    public const string MeterName = "Sikkerheit.Graph";
    private static readonly Meter Meter = new(MeterName);
    private static readonly Histogram<double> Waiting = Meter.CreateHistogram<double>("sikkerheit.graph.wait", "s");
    private static readonly Counter<long> Responses = Meter.CreateCounter<long>("sikkerheit.graph.responses");

    public static void Wait(GraphLimit limit, TimeSpan wait) =>
        Waiting.Record(wait.TotalSeconds, new KeyValuePair<string, object?>("limit", limit.ToString()));

    public static void Response(GraphLimit limit, int status, string kind) => Responses.Add(1,
        new KeyValuePair<string, object?>("limit", limit.ToString()),
        new KeyValuePair<string, object?>("kind", kind),
        new KeyValuePair<string, object?>("status", status switch
        {
            429 => "429", >= 500 and < 600 => "5xx", >= 400 and < 500 => "4xx",
            >= 300 and < 400 => "3xx", >= 200 and < 300 => "2xx", _ => "other",
        }));
}
