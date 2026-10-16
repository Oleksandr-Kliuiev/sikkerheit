using System.Diagnostics;
using Azure.Monitor.OpenTelemetry.AspNetCore;
using OpenTelemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace Sikkerheit.Host.Platform;

/// <summary>
/// Application Insights through OpenTelemetry (02 «Наблюдаемость»), without request bodies, tokens or query strings:
/// the Teams webhook carries its signature in the query, the consent return page carries tenant parameters (04).
/// </summary>
public static class Telemetry
{
    public static void Add(IServiceCollection services, IConfiguration configuration)
    {
        if (string.IsNullOrEmpty(configuration["APPLICATIONINSIGHTS_CONNECTION_STRING"]))
        {
            return;
        }
        // The scrubber is registered first, so it runs before the exporter's processor sees a span.
        services.ConfigureOpenTelemetryTracerProvider(tracing => tracing.AddProcessor(new QueryScrubber()));
        services.ConfigureOpenTelemetryMeterProvider(metrics => metrics.AddMeter(Agents.AgentMetrics.MeterName));
        services.AddOpenTelemetry().UseAzureMonitor();
    }

    /// <summary>Removes query strings from every span before export.</summary>
    public sealed class QueryScrubber : BaseProcessor<Activity>
    {
        private static readonly string[] UrlTags = ["url.full", "http.url", "http.target"];

        public override void OnEnd(Activity activity)
        {
            activity.SetTag("url.query", null);
            foreach (var tag in UrlTags)
            {
                if (activity.GetTagItem(tag) is string value && value.IndexOf('?', StringComparison.Ordinal) is var index and >= 0)
                {
                    activity.SetTag(tag, value[..index]);
                }
            }
            if (activity.DisplayName.IndexOf('?', StringComparison.Ordinal) is var name and >= 0)
            {
                activity.DisplayName = activity.DisplayName[..name];
            }
        }
    }
}
