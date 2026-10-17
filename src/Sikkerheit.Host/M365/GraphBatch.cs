using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sikkerheit.Host.M365;

public sealed partial class GraphClient
{
    /// <summary>Reserve whole batches immediately before each HTTP attempt; retry only transient subresponses.</summary>
    public async Task<IReadOnlyList<GraphBatchAnswer>> BatchGetAsync(Guid tenant, IReadOnlyList<string> paths,
        GraphLimit limit, CancellationToken ct)
    {
        var answers = new Dictionary<string, GraphBatchAnswer>(StringComparer.Ordinal);
        var pending = paths.Distinct(StringComparer.Ordinal).ToList();
        for (var attempt = 0; pending.Count > 0 && attempt < retry.Attempts; attempt++)
        {
            var retryLater = new List<string>();
            foreach (var chunk in pending.Chunk(GraphLimiter.BatchSize(limit)))
            {
                var request = new JsonObject
                {
                    ["requests"] = new JsonArray(chunk.Select((p, i) => (JsonNode)new JsonObject
                    {
                        ["id"] = i.ToString(CultureInfo.InvariantCulture), ["method"] = "GET", ["url"] = p,
                    }).ToArray()),
                };
                var body = await SendAsync(tenant, HttpMethod.Post, Absolute("v1.0/$batch"), request.ToJsonString(),
                    limit, chunk.Length, ct);
                if (body.ValueKind != JsonValueKind.Object || !body.TryGetProperty("responses", out var responses)
                    || responses.ValueKind != JsonValueKind.Array)
                {
                    throw new GraphException(GraphFailure.Temporary, 200, null, "Graph batch has no responses array");
                }
                var seen = new HashSet<int>();
                var pause = TimeSpan.Zero;
                var malformed = false;
                foreach (var response in responses.EnumerateArray())
                {
                    if (response.ValueKind != JsonValueKind.Object
                        || !response.TryGetProperty("status", out var code) || code.ValueKind != JsonValueKind.Number
                        || !code.TryGetInt32(out var status) || status is < 100 or > 599)
                    {
                        malformed = true;
                        continue;
                    }
                    // Preserve valid server cooldowns even when another response or its routing id is malformed.
                    if (Transient(status))
                    {
                        var after = GraphRetryAfter.Parse(response, clock.GetUtcNow()) ?? Backoff(attempt);
                        pause = after > pause ? after : pause;
                    }
                    if (!response.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String
                        || !int.TryParse(id.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out var index)
                        || index < 0 || index >= chunk.Length || !seen.Add(index))
                    {
                        malformed = true;
                        continue;
                    }
                    var url = chunk[index];
                    var payload = response.TryGetProperty("body", out var b) ? b.Clone() : default;
                    GraphMetrics.Response(limit, status, "request");
                    answers[url] = new GraphBatchAnswer(url, status, payload);
                    if (Transient(status))
                    {
                        retryLater.Add(url);
                    }
                }
                // An omitted subresponse is unavailable, never an invented success.
                foreach (var index in Enumerable.Range(0, chunk.Length).Where(i => !seen.Contains(i)))
                {
                    answers[chunk[index]] = new GraphBatchAnswer(chunk[index], 503, default);
                    retryLater.Add(chunk[index]);
                    var after = Backoff(attempt);
                    pause = after > pause ? after : pause;
                }
                // Includes the last allowed attempt; persist the longest server delay before any next chunk.
                await limiter.DeferAsync(limit, tenant, pause, ct);
                if (malformed) throw new GraphException(GraphFailure.Temporary, 200, null, "Graph batch has an invalid subresponse");
            }
            pending = retryLater;
        }
        return paths.Distinct(StringComparer.Ordinal).Select(p => answers[p]).ToList();
    }
}
