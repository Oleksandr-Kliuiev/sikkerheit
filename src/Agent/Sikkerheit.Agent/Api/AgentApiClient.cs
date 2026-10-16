using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sikkerheit.Contracts;

namespace Sikkerheit.Agent.Api;

/// <summary>Answer of the server: a body, a Problem or a failure of the transport.</summary>
public sealed record ApiResult(
    AgentOperation Operation, int Status, JsonElement? Body, string? ProblemCode, TimeSpan? RetryAfter, string? MinimumAgentVersion,
    Exception? Transport)
{
    public bool IsSuccess => Transport is null && Status is >= 200 and < 300;

    /// <summary>Actions of the agent: an answer without Problem or with a code outside the catalog and a network error are retry_backoff.</summary>
    public AgentActions Actions => IsSuccess
        ? AgentActions.None
        : ProblemCode is { } code && IsAgentCode(code)
            ? ProblemPolicy.Resolve(code, Operation, RetryAfter is not null)
            : AgentActions.RetryBackoff;

    private static bool IsAgentCode(string code) => Catalog.Problems.TryGetValue(code, out var p) && p.AgentAction != "—";
}

/// <summary>HTTPS client of the agent API (05, "API агента"). The base address is the hostname of the agent only.</summary>
public sealed class AgentApiClient(HttpClient http, ContractSchemas schemas)
{
    private static readonly Dictionary<string, string> NoHeaders = [];
    private static readonly MediaTypeHeaderValue Json = new("application/json");

    public Task<ApiResult> CreateChallengeAsync(string purpose, string? deviceId, CancellationToken ct)
    {
        var body = new JsonObject { ["purpose"] = purpose };
        if (deviceId is not null)
        {
            body["deviceId"] = deviceId;
        }
        return SendAsync(AgentOperation.CreateChallenge, "/api/v1/agent/challenges", Bytes(body), NoHeaders, ct);
    }

    /// <summary>The body is sent as is: a retry after a lost answer sends the same bytes (idempotency by requestHash).</summary>
    public Task<ApiResult> EnrollAsync(byte[] body, string enrollmentKey, CancellationToken ct) =>
        SendAsync(AgentOperation.Enroll, "/api/v1/agent/enrollments", body,
            new Dictionary<string, string> { ["Authorization"] = "Enrollment " + enrollmentKey }, ct);

    public Task<ApiResult> CreateSessionAsync(string deviceId, string nonce, string signature, CancellationToken ct) =>
        SendAsync(AgentOperation.CreateSession, "/api/v1/agent/sessions",
            Bytes(new JsonObject { ["deviceId"] = deviceId, ["nonce"] = nonce, ["signature"] = signature }), NoHeaders, ct);

    public Task<ApiResult> CheckInAsync(JsonObject checkIn, string token, CancellationToken ct) =>
        SendAsync(AgentOperation.CheckIn, "/api/v1/agent/check-ins", Bytes(checkIn), Bearer(token), ct);

    public Task<ApiResult> SubmitScanAsync(string scanId, byte[] body, string token, DateTimeOffset sentAt, CancellationToken ct) =>
        SendAsync(AgentOperation.SubmitScan, "/api/v1/agent/scans", body,
            new Dictionary<string, string>
            {
                ["Authorization"] = "Bearer " + token,
                ["Idempotency-Key"] = scanId,
                ["Sikkerheit-Sent-At"] = sentAt.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture),
            }, ct);

    /// <summary>Validates an answer by the schema of the contract: a body that does not match is a failed answer.</summary>
    public bool Matches(string component, JsonElement body) => schemas.ValidateComponent(component, body).Count == 0;

    private static Dictionary<string, string> Bearer(string token) => new() { ["Authorization"] = "Bearer " + token };

    private static byte[] Bytes(JsonObject body) => System.Text.Encoding.UTF8.GetBytes(body.ToJsonString());

    private async Task<ApiResult> SendAsync(
        AgentOperation operation, string path, byte[] body, IReadOnlyDictionary<string, string> headers, CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new ByteArrayContent(body) };
            request.Content.Headers.ContentType = Json;
            foreach (var (name, value) in headers)
            {
                request.Headers.TryAddWithoutValidation(name, value);
            }
            using var response = await http.SendAsync(request, ct).ConfigureAwait(false);
            var bytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            JsonElement? json = null;
            try
            {
                using var document = JsonDocument.Parse(bytes);
                json = document.RootElement.Clone();
            }
            catch (JsonException)
            {
                // An answer that is not JSON has no Problem.
            }
            var status = (int)response.StatusCode;
            if (status is >= 200 and < 300)
            {
                return new ApiResult(operation, status, json, null, null, null, null);
            }
            return new ApiResult(operation, status, json, Code(json), RetryAfter(response), Minimum(json), null);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or IOException
            && !ct.IsCancellationRequested)
        {
            return new ApiResult(operation, 0, null, null, null, null, exception);
        }
    }

    private static string? Code(JsonElement? json) =>
        json is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String
            ? code.GetString()
            : null;

    private static string? Minimum(JsonElement? json) =>
        json is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty("minimumAgentVersion", out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

    private static TimeSpan? RetryAfter(HttpResponseMessage response)
    {
        var header = response.Headers.RetryAfter;
        if (header?.Delta is { } delta)
        {
            return delta;
        }
        return header?.Date is { } date ? (date - DateTimeOffset.UtcNow is { } wait && wait > TimeSpan.Zero ? wait : TimeSpan.Zero) : null;
    }
}
