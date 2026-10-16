using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

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

/// <summary>Graph rate classes of 02 «Сбор данных Microsoft 365».</summary>
public enum GraphLimit
{
    Default,
    AuthMethods,
    ConditionalAccess,
    SignInActivity,
}

/// <summary>
/// Sliding-window limiter shared by the whole service: authentication methods and reports — 5 requests per 10 s per
/// tenant and 122 per 10 s for all tenants; Conditional Access — 1 per second per tenant; signInActivity — 10 per
/// minute for all tenants. Each request inside a JSON batch counts separately.
/// </summary>
public sealed class GraphLimiter(TimeProvider clock)
{
    private readonly Dictionary<string, Queue<DateTimeOffset>> _windows = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _lock = new(1, 1);

    public async Task WaitAsync(GraphLimit limit, Guid tenant, int requests, CancellationToken ct)
    {
        for (var i = 0; i < requests; i++)
        {
            await WaitOneAsync(limit, tenant, ct);
        }
    }

    private async Task WaitOneAsync(GraphLimit limit, Guid tenant, CancellationToken ct)
    {
        var rules = limit switch
        {
            GraphLimit.AuthMethods => new[] { ($"am:{tenant}", 5, TimeSpan.FromSeconds(10)), ("am:all", 122, TimeSpan.FromSeconds(10)) },
            GraphLimit.ConditionalAccess => [($"ca:{tenant}", 1, TimeSpan.FromSeconds(1))],
            GraphLimit.SignInActivity => [("si:all", 10, TimeSpan.FromMinutes(1))],
            _ => [],
        };
        if (rules.Length == 0)
        {
            return;
        }
        while (true)
        {
            TimeSpan wait;
            await _lock.WaitAsync(ct);
            try
            {
                var now = clock.GetUtcNow();
                wait = TimeSpan.Zero;
                foreach (var (key, max, window) in rules)
                {
                    var queue = Window(key);
                    while (queue.Count > 0 && queue.Peek() <= now - window)
                    {
                        queue.Dequeue();
                    }
                    if (queue.Count >= max)
                    {
                        var free = queue.Peek() + window - now;
                        wait = free > wait ? free : wait;
                    }
                }
                if (wait <= TimeSpan.Zero)
                {
                    foreach (var (key, _, _) in rules)
                    {
                        Window(key).Enqueue(now);
                    }
                    return;
                }
            }
            finally
            {
                _lock.Release();
            }
            await Task.Delay(wait, clock, ct);
        }
    }

    private Queue<DateTimeOffset> Window(string key)
    {
        if (!_windows.TryGetValue(key, out var queue))
        {
            queue = new Queue<DateTimeOffset>();
            _windows[key] = queue;
        }
        return queue;
    }
}

/// <summary>All pages of a collection and whether every page was received.</summary>
public sealed record GraphPages(IReadOnlyList<JsonElement> Items, bool Complete);

/// <summary>One answer of a JSON batch.</summary>
public sealed record GraphBatchAnswer(string Url, int Status, JsonElement Body);

public sealed class GraphRetryPolicy
{
    public int Attempts { get; init; } = 4;
    public TimeSpan BaseDelay { get; init; } = TimeSpan.FromSeconds(1);
    public TimeSpan MaxRetryAfter { get; init; } = TimeSpan.FromMinutes(2);
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>
/// Read-only Graph client: fixed paths on graph.microsoft.com only, next pages only by @odata.nextLink of the same
/// host and path, Retry-After always honoured, exponential pause without it.
/// </summary>
public sealed class GraphClient(HttpClient http, IGraphTokenProvider tokens, GraphLimiter limiter, TimeProvider clock,
    GraphRetryPolicy retry)
{
    public const string Host = "graph.microsoft.com";
    private const int BatchSize = 20;

    public async Task<JsonElement> GetAsync(Guid tenant, string path, GraphLimit limit, CancellationToken ct)
    {
        await limiter.WaitAsync(limit, tenant, 1, ct);
        return await SendAsync(tenant, HttpMethod.Get, Absolute(path), null, ct);
    }

    public async Task<GraphPages> GetAllPagesAsync(Guid tenant, string path, GraphLimit limit, CancellationToken ct,
        int maxPages = 1000)
    {
        var items = new List<JsonElement>();
        var url = Absolute(path);
        var expectedPath = url.AbsolutePath;
        for (var page = 0; page < maxPages; page++)
        {
            await limiter.WaitAsync(limit, tenant, 1, ct);
            var body = await SendAsync(tenant, HttpMethod.Get, url, null, ct);
            if (body.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array)
            {
                items.AddRange(value.EnumerateArray().Select(e => e.Clone()));
            }
            if (!body.TryGetProperty("@odata.nextLink", out var next) || next.ValueKind != JsonValueKind.String)
            {
                return new GraphPages(items, true);
            }
            if (!Uri.TryCreate(next.GetString(), UriKind.Absolute, out var nextUrl)
                || nextUrl.Scheme != Uri.UriSchemeHttps || !string.Equals(nextUrl.Host, Host, StringComparison.OrdinalIgnoreCase)
                || nextUrl.AbsolutePath != expectedPath)
            {
                // A next link to another host or path is not followed: the module becomes partial.
                return new GraphPages(items, false);
            }
            url = nextUrl;
        }
        return new GraphPages(items, false);
    }

    /// <summary>GET requests in JSON batches of up to 20; sub-requests answered 429 are retried after Retry-After.</summary>
    public async Task<IReadOnlyList<GraphBatchAnswer>> BatchGetAsync(Guid tenant, IReadOnlyList<string> paths,
        GraphLimit limit, CancellationToken ct)
    {
        var answers = new Dictionary<string, GraphBatchAnswer>(StringComparer.Ordinal);
        var pending = paths.Distinct(StringComparer.Ordinal).ToList();
        for (var attempt = 0; pending.Count > 0 && attempt < retry.Attempts; attempt++)
        {
            var retryLater = new List<string>();
            var pause = TimeSpan.Zero;
            foreach (var chunk in pending.Chunk(BatchSize))
            {
                await limiter.WaitAsync(limit, tenant, chunk.Length, ct);
                var request = new JsonObject
                {
                    ["requests"] = new JsonArray(chunk.Select((p, i) => (JsonNode)new JsonObject
                    {
                        ["id"] = i.ToString(CultureInfo.InvariantCulture),
                        ["method"] = "GET",
                        ["url"] = p,
                    }).ToArray()),
                };
                var body = await SendAsync(tenant, HttpMethod.Post, Absolute("v1.0/$batch"), request.ToJsonString(), ct);
                foreach (var response in body.GetProperty("responses").EnumerateArray())
                {
                    var index = int.Parse(response.GetProperty("id").GetString()!, CultureInfo.InvariantCulture);
                    var url = chunk[index];
                    var status = response.GetProperty("status").GetInt32();
                    var payload = response.TryGetProperty("body", out var b) ? b.Clone() : default;
                    if (status is 429 or 503 or 504)
                    {
                        retryLater.Add(url);
                        var after = SubRetryAfter(response);
                        pause = after > pause ? after : pause;
                        answers[url] = new GraphBatchAnswer(url, status, payload);
                        continue;
                    }
                    answers[url] = new GraphBatchAnswer(url, status, payload);
                }
            }
            pending = retryLater;
            if (pending.Count > 0)
            {
                await Task.Delay(pause > TimeSpan.Zero ? pause : Backoff(attempt), clock, ct);
            }
        }
        return paths.Distinct(StringComparer.Ordinal).Select(p => answers[p]).ToList();
    }

    private static Uri Absolute(string path) => new($"https://{Host}/{path.TrimStart('/')}");

    private async Task<JsonElement> SendAsync(Guid tenant, HttpMethod method, Uri url, string? json, CancellationToken ct)
    {
        if (!string.Equals(url.Host, Host, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Graph requests go only to graph.microsoft.com");
        }
        for (var attempt = 0; ; attempt++)
        {
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
                if (response.IsSuccessStatusCode)
                {
                    return text.Length == 0 ? default : JsonDocument.Parse(text).RootElement.Clone();
                }
                var code = ErrorCode(text);
                if (status is 429 or 503 or 504 or >= 500)
                {
                    if (attempt + 1 >= retry.Attempts)
                    {
                        throw new GraphException(GraphFailure.Temporary, status, code, $"Graph {status} after retries");
                    }
                    await Task.Delay(RetryAfter(response) ?? Backoff(attempt), clock, ct);
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

    private TimeSpan? RetryAfter(HttpResponseMessage response)
    {
        var header = response.Headers.RetryAfter;
        if (header?.Delta is { } delta)
        {
            return delta < retry.MaxRetryAfter ? delta : retry.MaxRetryAfter;
        }
        if (header?.Date is { } date)
        {
            var wait = date - clock.GetUtcNow();
            return wait < TimeSpan.Zero ? TimeSpan.Zero : wait < retry.MaxRetryAfter ? wait : retry.MaxRetryAfter;
        }
        return null;
    }

    private TimeSpan SubRetryAfter(JsonElement response)
    {
        if (response.TryGetProperty("headers", out var headers) && headers.ValueKind == JsonValueKind.Object)
        {
            foreach (var header in headers.EnumerateObject())
            {
                if (header.Name.Equals("Retry-After", StringComparison.OrdinalIgnoreCase)
                    && int.TryParse(header.Value.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
                {
                    var delay = TimeSpan.FromSeconds(seconds);
                    return delay < retry.MaxRetryAfter ? delay : retry.MaxRetryAfter;
                }
            }
        }
        return retry.BaseDelay;
    }

    private TimeSpan Backoff(int attempt) => retry.BaseDelay * Math.Pow(2, attempt);

    private static string? ErrorCode(string text)
    {
        try
        {
            using var document = JsonDocument.Parse(text);
            return document.RootElement.TryGetProperty("error", out var error) && error.TryGetProperty("code", out var code)
                ? code.GetString()
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
