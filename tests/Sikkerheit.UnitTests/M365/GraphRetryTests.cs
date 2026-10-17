using System.Net;
using System.Text;
using System.Text.Json;
using Sikkerheit.Host.M365;

namespace Sikkerheit.UnitTests.M365;

public sealed class GraphRetryTests
{
    private static readonly Guid Tenant = Guid.NewGuid();

    [Theory]
    [InlineData("600", 600)]
    [InlineData("0", 0)]
    [InlineData(" 1800 ", 1800)]
    [InlineData("Sat, 17 Oct 2026 12:10:00 GMT", 600)]
    [InlineData("Sat, 17 Oct 2026 11:00:00 GMT", 0)]
    [InlineData("-1", null)]
    [InlineData("broken", null)]
    public void Retry_after_accepts_seconds_and_http_dates_without_a_two_minute_cap(string value, int? seconds)
    {
        var parsed = GraphRetryAfter.Parse(value, new ManualClock().GetUtcNow());
        Assert.Equal(seconds is null ? null : TimeSpan.FromSeconds(seconds.Value), parsed);
    }

    [Theory]
    [InlineData("600")]
    [InlineData("Sat, 17 Oct 2026 12:10:00 GMT")]
    public async Task Single_request_waits_the_full_server_delay_and_reserves_each_attempt(string value)
    {
        var clock = new ManualClock();
        var store = new RecordingStore(clock);
        using var handler = new Handler((_, n) => n == 1 ? Response(429, "{}", value) : Response(200, "{\"value\":[]}"));
        using var http = new HttpClient(handler);
        var client = Client(http, store, clock);
        var task = client.GetAsync(Tenant, "v1.0/users", GraphLimit.AuthMethods, TestContext.Current.CancellationToken);
        Assert.Equal(1, clock.Pending);
        clock.Advance(TimeSpan.FromSeconds(599));
        Assert.False(task.IsCompleted);
        Assert.Equal(1, handler.Count);
        clock.Advance(TimeSpan.FromSeconds(1));
        await task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.Equal(2, handler.Count);
        Assert.Equal(new[] { 1, 1 }, store.Accepted);
    }

    [Fact]
    public async Task Huge_retry_after_remains_cancellable_without_an_early_request()
    {
        var clock = new ManualClock();
        var store = new RecordingStore(clock);
        using var handler = new Handler((_, _) => Response(429, "{}", "18446744073709551615"));
        using var http = new HttpClient(handler);
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var task = Client(http, store, clock).GetAsync(Tenant, "v1.0/users", GraphLimit.Default, cancel.Token);
        Assert.Equal(1, clock.Pending);
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        Assert.Equal(1, handler.Count);
    }

    [Fact]
    public async Task Batches_fit_the_tenant_window_and_reserve_the_whole_chunk()
    {
        var clock = new ManualClock();
        var store = new RecordingStore(clock);
        var batches = new List<int>();
        using var handler = new Handler((request, _) => Batch(request, (id, _) => 200, batches));
        using var http = new HttpClient(handler);
        var paths = Enumerable.Range(0, 11).Select(i => $"/users/{i}/authentication/methods").ToArray();
        var result = await Client(http, store, clock).BatchGetAsync(Tenant, paths, GraphLimit.AuthMethods,
            TestContext.Current.CancellationToken);
        Assert.Equal(new[] { 5, 5, 1 }, batches);
        Assert.Equal(batches, store.Accepted);
        Assert.Equal(11, result.Count);
    }

    [Fact]
    public async Task Batch_retries_only_failed_subrequests_after_the_longest_delay()
    {
        var clock = new ManualClock();
        var store = new RecordingStore(clock);
        var batches = new List<int>();
        using var handler = new Handler((request, n) =>
        {
            if (n != 1) { return Batch(request, (_, _) => 200, batches); }
            batches.Add(3);
            return Response(200, """
                {"responses":[{"id":"0","status":200,"body":{}},
                  {"id":"1","status":429,"headers":{"Retry-After":"600"}},
                  {"id":"2","status":503,"headers":{"retry-AFTER":"Sat, 17 Oct 2026 12:20:00 GMT"}}]}
                """);
        });
        using var http = new HttpClient(handler);
        var task = Client(http, store, clock).BatchGetAsync(Tenant, ["/users/1", "/users/2", "/users/3"],
            GraphLimit.AuthMethods, TestContext.Current.CancellationToken);
        Assert.Equal(1, clock.Pending);
        clock.Advance(TimeSpan.FromSeconds(1199));
        Assert.False(task.IsCompleted);
        clock.Advance(TimeSpan.FromSeconds(1));
        var result = await task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.Equal(new[] { 3, 2 }, batches);
        Assert.All(result, answer => Assert.Equal(200, answer.Status));
        Assert.Equal(batches, store.Accepted);
    }

    [Fact]
    public async Task Transport_retries_charge_every_subrequest_again()
    {
        var clock = new ManualClock();
        var store = new RecordingStore(clock);
        var batches = new List<int>();
        using var handler = new Handler((request, n) => n == 1 ? Response(503, "{}", "600")
            : Batch(request, (_, _) => 200, batches));
        using var http = new HttpClient(handler);
        var task = Client(http, store, clock).BatchGetAsync(Tenant, ["/users/1", "/users/2"], GraphLimit.AuthMethods,
            TestContext.Current.CancellationToken);
        clock.Advance(TimeSpan.FromSeconds(600));
        await task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.Equal(new[] { 2, 2 }, store.Accepted);
    }

    [Fact]
    public async Task Final_failed_attempt_publishes_cooldown_without_waiting_uselessly()
    {
        var clock = new ManualClock();
        var store = new RecordingStore(clock);
        using var handler = new Handler((_, _) => Response(429, "{}", "600"));
        using var http = new HttpClient(handler);
        var client = Client(http, store, clock, attempts: 1);
        await Assert.ThrowsAsync<GraphException>(() => client.GetAsync(Tenant, "v1.0/users", GraphLimit.Default,
            TestContext.Current.CancellationToken));
        Assert.Equal(clock.GetUtcNow().AddSeconds(600), store.BlockedUntil);
        Assert.Equal(0, clock.Pending);
    }

    [Fact]
    public async Task Missing_batch_response_is_unavailable_and_final_subresponse_delay_is_preserved()
    {
        var clock = new ManualClock();
        var store = new RecordingStore(clock);
        using var handler = new Handler((_, _) => Response(200,
            "{\"responses\":[{\"id\":\"0\",\"status\":429,\"headers\":{\"retry-after\":600}}]}"));
        using var http = new HttpClient(handler);
        var result = await Client(http, store, clock, attempts: 1).BatchGetAsync(Tenant, ["/users/1", "/users/2"],
            GraphLimit.AuthMethods, TestContext.Current.CancellationToken);
        Assert.Equal(new[] { 429, 503 }, result.Select(a => a.Status));
        Assert.Equal(clock.GetUtcNow().AddSeconds(600), store.BlockedUntil);
        Assert.Equal(0, clock.Pending);
    }

    [Theory]
    [InlineData(GraphLimit.AuthMethods, 6)]
    [InlineData(GraphLimit.ConditionalAccess, 2)]
    [InlineData(GraphLimit.SignInActivity, 11)]
    [InlineData(GraphLimit.Default, 21)]
    [InlineData(GraphLimit.Default, 0)]
    public async Task Limiter_rejects_an_impossible_atomic_batch(GraphLimit limit, int requests)
    {
        var clock = new ManualClock();
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => new GraphLimiter(new RecordingStore(clock), clock)
            .WaitAsync(limit, Tenant, requests, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Network_retry_reserves_quota_again_and_uses_backoff_without_server_headers()
    {
        var clock = new ManualClock();
        var store = new RecordingStore(clock);
        using var handler = new Handler((_, n) => n == 1 ? throw new HttpRequestException("synthetic network failure") : Response(200, "{}"));
        using var http = new HttpClient(handler);
        var task = Client(http, store, clock).GetAsync(Tenant, "v1.0/users", GraphLimit.AuthMethods, TestContext.Current.CancellationToken);
        clock.Advance(TimeSpan.FromMilliseconds(999));
        Assert.False(task.IsCompleted);
        Assert.Equal(1, handler.Count);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        await task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.Equal(new[] { 1, 1 }, store.Accepted);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{\"responses\":[null]}")]
    [InlineData("{\"responses\":[{\"id\":\"0\",\"status\":\"200\"}]}")]
    [InlineData("{\"responses\":[{\"id\":\"10\",\"status\":200}]}")]
    public async Task Malformed_batch_payloads_are_temporary_failures(string json)
    {
        var clock = new ManualClock();
        using var handler = new Handler((_, _) => Response(200, json));
        using var http = new HttpClient(handler);
        var error = await Assert.ThrowsAsync<GraphException>(() => Client(http, new RecordingStore(clock), clock)
            .BatchGetAsync(Tenant, ["/users/1"], GraphLimit.AuthMethods, TestContext.Current.CancellationToken));
        Assert.Equal(GraphFailure.Temporary, error.Failure);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("{\"value\":null}")]
    [InlineData("{\"value\":[null]}")]
    [InlineData("{\"value\":[],\"@odata.nextLink\":false}")]
    public async Task Malformed_collection_page_keeps_received_users_but_never_confirms_completeness(string malformed)
    {
        var clock = new ManualClock();
        using var handler = new Handler((_, n) => Response(200, n == 1
            ? "{\"value\":[{\"id\":\"previous-user\"}],\"@odata.nextLink\":\"https://graph.microsoft.com/v1.0/users?$skiptoken=2\"}"
            : malformed));
        using var http = new HttpClient(handler);
        var pages = await Client(http, new RecordingStore(clock), clock).GetAllPagesAsync(Tenant, "v1.0/users",
            GraphLimit.Default, TestContext.Current.CancellationToken);
        Assert.False(pages.Complete);
        Assert.Equal("previous-user", Assert.Single(pages.Items).GetProperty("id").GetString());
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("{\"error\":\"unavailable\"}")]
    [InlineData("{\"error\":{\"code\":123}}")]
    public async Task Malformed_error_body_does_not_discard_server_cooldown(string body)
    {
        var clock = new ManualClock();
        var store = new RecordingStore(clock);
        using var handler = new Handler((_, _) => Response(429, body, "600"));
        using var http = new HttpClient(handler);
        var error = await Assert.ThrowsAsync<GraphException>(() => Client(http, store, clock, attempts: 1)
            .GetAsync(Tenant, "v1.0/users", GraphLimit.Default, TestContext.Current.CancellationToken));
        Assert.Equal(GraphFailure.Temporary, error.Failure);
        Assert.Equal(clock.GetUtcNow().AddSeconds(600), store.BlockedUntil);
    }

    [Theory]
    [InlineData("null,{\"id\":\"0\",\"status\":429,\"headers\":{\"Retry-After\":\"600\"}}")]
    [InlineData("{\"id\":\"0\",\"status\":429,\"headers\":{\"Retry-After\":\"600\"}},null")]
    public async Task Malformed_batch_sibling_does_not_discard_server_cooldown(string responses)
    {
        var clock = new ManualClock();
        var store = new RecordingStore(clock);
        using var handler = new Handler((_, _) => Response(200, "{\"responses\":[" + responses + "]}"));
        using var http = new HttpClient(handler);
        await Assert.ThrowsAsync<GraphException>(() => Client(http, store, clock, attempts: 1)
            .BatchGetAsync(Tenant, ["/users/1"], GraphLimit.AuthMethods, TestContext.Current.CancellationToken));
        Assert.Equal(clock.GetUtcNow().AddSeconds(600), store.BlockedUntil);
    }

    private static GraphClient Client(HttpClient http, RecordingStore store, ManualClock clock, int attempts = 4) =>
        new(http, new Tokens(), new GraphLimiter(store, clock), clock, new GraphRetryPolicy { Attempts = attempts });

    private static HttpResponseMessage Response(int status, string json, string? after = null)
    {
        var response = new HttpResponseMessage((HttpStatusCode)status)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
        if (after is not null) { response.Headers.TryAddWithoutValidation("Retry-After", after); }
        return response;
    }

    private static HttpResponseMessage Batch(HttpRequestMessage request, Func<string, int, int> status, List<int> batches,
        string? after = null)
    {
        var body = request.Content!.ReadAsStringAsync(TestContext.Current.CancellationToken).GetAwaiter().GetResult();
        var items = JsonDocument.Parse(body).RootElement.GetProperty("requests").EnumerateArray().ToArray();
        batches.Add(items.Length);
        return Response(200, JsonSerializer.Serialize(new
        {
            responses = items.Select((item, i) => new
            {
                id = item.GetProperty("id").GetString(), status = status(item.GetProperty("id").GetString()!, i),
                headers = new Dictionary<string, string?> { ["Retry-After"] = after }, body = new { value = Array.Empty<object>() },
            }),
        }));
    }

    private sealed class Tokens : IGraphTokenProvider
    {
        public Task<string> GetTokenAsync(Guid tenantId, CancellationToken ct) => Task.FromResult("synthetic");
    }

    private sealed class Handler(Func<HttpRequestMessage, int, HttpResponseMessage> answer) : HttpMessageHandler
    {
        public int Count { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(answer(request, ++Count));
    }

    private sealed class RecordingStore(ManualClock clock) : IGraphRateStore
    {
        public List<int> Accepted { get; } = [];
        public DateTimeOffset BlockedUntil { get; private set; } = DateTimeOffset.MinValue;

        public Task<TimeSpan> TryAcquireAsync(GraphLimit limit, Guid tenant, int requests, CancellationToken ct)
        {
            var delay = BlockedUntil - clock.GetUtcNow();
            if (delay <= TimeSpan.Zero) { Accepted.Add(requests); }
            return Task.FromResult(delay > TimeSpan.Zero ? delay : TimeSpan.Zero);
        }

        public Task DeferAsync(GraphLimit limit, Guid tenant, TimeSpan delay, CancellationToken ct)
        {
            var until = delay > DateTimeOffset.MaxValue - clock.GetUtcNow() ? DateTimeOffset.MaxValue : clock.GetUtcNow() + delay;
            BlockedUntil = until > BlockedUntil ? until : BlockedUntil;
            return Task.CompletedTask;
        }
    }
}
