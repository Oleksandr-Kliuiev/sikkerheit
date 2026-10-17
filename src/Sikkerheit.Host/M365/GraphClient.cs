using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Sikkerheit.Host.M365;

/// <summary>Why a Graph call did not give data; maps to module capability statuses (03 «Возможности подключения»).</summary>
public enum GraphFailure
{
    Forbidden,
    NotFound,
    Temporary,
    Unauthorized,
}

public sealed class GraphException(GraphFailure failure, int status, string? code, string message) : Exception(message)
{
    public GraphFailure Failure { get; } = failure;
    public int Status { get; } = status;
    public string? Code { get; } = code;
}

/// <summary>An app-only token could not be obtained. FailureCode: consent_missing, credential_error or temporary_error.</summary>
public sealed class GraphTokenException(string failureCode, string message, Exception? inner = null) : Exception(message, inner)
{
    public string FailureCode { get; } = failureCode;
}

public interface IGraphTokenProvider
{
    Task<string> GetTokenAsync(Guid tenantId, CancellationToken ct);
}

/// <summary>All pages of a collection and whether every page was received.</summary>
public sealed record GraphPages(IReadOnlyList<JsonElement> Items, bool Complete);

/// <summary>One answer of a JSON batch.</summary>
public sealed record GraphBatchAnswer(string Url, int Status, JsonElement Body);

public sealed class GraphRetryPolicy
{
    public int Attempts { get; init; } = 4;
    public TimeSpan BaseDelay { get; init; } = TimeSpan.FromSeconds(1);
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>
/// Read-only Graph client: fixed paths on graph.microsoft.com only, next pages only by @odata.nextLink of the same
/// host and path, Retry-After always honoured, exponential pause without it.
/// </summary>
public sealed partial class GraphClient(HttpClient http, IGraphTokenProvider tokens, GraphLimiter limiter, TimeProvider clock,
    GraphRetryPolicy retry)
{
    public const string Host = "graph.microsoft.com";

    public async Task<JsonElement> GetAsync(Guid tenant, string path, GraphLimit limit, CancellationToken ct)
    {
        return await SendAsync(tenant, HttpMethod.Get, Absolute(path), null, limit, 1, ct);
    }

    public async Task<GraphPages> GetAllPagesAsync(Guid tenant, string path, GraphLimit limit, CancellationToken ct,
        int maxPages = 1000)
    {
        var items = new List<JsonElement>();
        var url = Absolute(path);
        var expectedPath = url.AbsolutePath;
        for (var page = 0; page < maxPages; page++)
        {
            var body = await SendAsync(tenant, HttpMethod.Get, url, null, limit, 1, ct);
            if (body.ValueKind != JsonValueKind.Object || !body.TryGetProperty("value", out var value)
                || value.ValueKind != JsonValueKind.Array || value.EnumerateArray().Any(item => item.ValueKind != JsonValueKind.Object))
            {
                // An incomplete user/role inventory must never retire missing subjects or prove a role's removal.
                return new GraphPages(items, false);
            }
            items.AddRange(value.EnumerateArray().Select(e => e.Clone()));
            if (!body.TryGetProperty("@odata.nextLink", out var next))
            {
                return new GraphPages(items, true);
            }
            if (next.ValueKind != JsonValueKind.String || !Uri.TryCreate(next.GetString(), UriKind.Absolute, out var nextUrl)
                || nextUrl.Scheme != Uri.UriSchemeHttps || !string.Equals(nextUrl.Host, Host, StringComparison.OrdinalIgnoreCase)
                || !nextUrl.IsDefaultPort || nextUrl.UserInfo.Length > 0 || nextUrl.AbsolutePath != expectedPath)
            {
                // A next link to another host or path is not followed: the module becomes partial.
                return new GraphPages(items, false);
            }
            url = nextUrl;
        }
        return new GraphPages(items, false);
    }

    private static Uri Absolute(string path) => new($"https://{Host}/{path.TrimStart('/')}");

    private async Task<JsonElement> SendAsync(Guid tenant, HttpMethod method, Uri url, string? json, GraphLimit limit,
        int requests, CancellationToken ct)
    {
        if (!string.Equals(url.Host, Host, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Graph requests go only to graph.microsoft.com");
        }
        for (var attempt = 0; ; attempt++)
        {
            await limiter.WaitAsync(limit, tenant, requests, ct);
            var token = await tokens.GetTokenAsync(tenant, ct);
            using var request = new HttpRequestMessage(method, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (json is not null)
            {
                request.Content = new StringContent(json, Encoding.UTF8, "application/json");
            }
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(retry.RequestTimeout);
            HttpResponseMessage response;
            try
            {
                response = await http.SendAsync(request, HttpCompletionOption.ResponseContentRead, timeout.Token);
            }
            catch (Exception error) when (!ct.IsCancellationRequested
                                          && error is HttpRequestException or TaskCanceledException)
            {
                if (attempt + 1 >= retry.Attempts)
                {
                    throw new GraphException(GraphFailure.Temporary, 0, null, "Graph request failed: " + error.Message);
                }
                await Task.Delay(Backoff(attempt), clock, ct);
                continue;
            }
            using (response)
            {
                var text = await response.Content.ReadAsStringAsync(ct);
                var status = (int)response.StatusCode;
                GraphMetrics.Response(limit, status, method == HttpMethod.Post ? "batch" : "request");
                if (response.IsSuccessStatusCode)
                {
                    try
                    {
                        if (text.Length == 0) { return default; }
                        using var document = JsonDocument.Parse(text);
                        return document.RootElement.Clone();
                    }
                    catch (JsonException)
                    {
                        throw new GraphException(GraphFailure.Temporary, status, null, "Graph returned invalid JSON");
                    }
                }
                var code = ErrorCode(text);
                if (Transient(status))
                {
                    var after = response.Headers.TryGetValues("Retry-After", out var values)
                        ? GraphRetryAfter.Parse(values.FirstOrDefault(), clock.GetUtcNow()) : null;
                    // Publish even the final response's cooldown: another request/instance must honour it too.
                    await limiter.DeferAsync(limit, tenant, after ?? Backoff(attempt), ct);
                    if (attempt + 1 >= retry.Attempts)
                    {
                        throw new GraphException(GraphFailure.Temporary, status, code, $"Graph {status} after retries");
                    }
                    continue;
                }
                throw status switch
                {
                    (int)HttpStatusCode.Forbidden => new GraphException(GraphFailure.Forbidden, status, code, "Graph 403"),
                    (int)HttpStatusCode.NotFound => new GraphException(GraphFailure.NotFound, status, code, "Graph 404"),
                    (int)HttpStatusCode.Unauthorized => new GraphException(GraphFailure.Unauthorized, status, code, "Graph 401"),
                    _ => new GraphException(GraphFailure.Temporary, status, code, $"Graph {status}"),
                };
            }
        }
    }

    private static bool Transient(int status) => status == 429 || status >= 500;

    private TimeSpan Backoff(int attempt) => retry.BaseDelay * Math.Pow(2, attempt);

    private static string? ErrorCode(string text)
    {
        try
        {
            using var document = JsonDocument.Parse(text);
            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object
                && error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String
                ? code.GetString()
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
