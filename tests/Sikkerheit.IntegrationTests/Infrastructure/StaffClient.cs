using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Sikkerheit.Contracts;

namespace Sikkerheit.IntegrationTests.Infrastructure;

/// <summary>A signed-in staff member: session cookie, CSRF header and contract checks of every JSON answer.</summary>
public sealed class StaffClient
{
    private static readonly ContractSchemas Schemas = new();
    private readonly HttpClient _http;

    private StaffClient(HttpClient http, Guid entraUserId, string csrf)
    {
        _http = http;
        EntraUserId = entraUserId;
        Csrf = csrf;
    }

    public Guid EntraUserId { get; }
    public string Csrf { get; }

    public static async Task<StaffClient> SignInAsync(ApiFactory factory, params string[] roles)
    {
        var http = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = true });
        var id = Guid.NewGuid();
        var response = await http.PostAsJsonAsync("/auth/dev/login", new { entraUserId = id, displayName = "Test " + roles[0], roles });
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return new StaffClient(http, id, body.GetProperty("csrfToken").GetString()!);
    }

    public static HttpClient Anonymous(ApiFactory factory) =>
        factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = true });

    public Task<Answer> GetAsync(string path, string? component = null) => SendAsync(HttpMethod.Get, path, null, component);

    public Task<Answer> PostAsync(string path, object body, string? component = null, string? ifMatch = null, bool csrf = true) =>
        SendAsync(HttpMethod.Post, path, JsonSerializer.Serialize(body), component, ifMatch, csrf);

    public Task<Answer> PatchAsync(string path, object body, string? component = null) =>
        SendAsync(HttpMethod.Patch, path, JsonSerializer.Serialize(body), component);

    public async Task<Answer> SendAsync(HttpMethod method, string path, string? json, string? component,
        string? ifMatch = null, bool csrf = true, string contentType = "application/json", string? csrfOverride = null)
    {
        using var request = new HttpRequestMessage(method, path);
        if (json is not null)
        {
            request.Content = new StringContent(json, Encoding.UTF8);
            request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
        }
        if (csrf)
        {
            request.Headers.Add("X-CSRF-Token", csrfOverride ?? Csrf);
        }
        if (ifMatch is not null)
        {
            request.Headers.TryAddWithoutValidation("If-Match", ifMatch);
        }
        using var response = await _http.SendAsync(request);
        return await Answer.ReadAsync(response, component);
    }

    /// <summary>A file download: status, all headers and the raw body; error answers are checked against Problem.</summary>
    public async Task<FileAnswer> DownloadAsync(string path)
    {
        using var response = await _http.GetAsync(path);
        var body = await response.Content.ReadAsByteArrayAsync();
        // Raw values as the service sent them: parsed headers would be normalized (Cache-Control reorders directives).
        var headers = response.Headers.NonValidated.Concat(response.Content.Headers.NonValidated)
            .ToDictionary(h => h.Key, h => string.Join(", ", h.Value), StringComparer.OrdinalIgnoreCase);
        string? code = null;
        if ((int)response.StatusCode >= 400)
        {
            var problem = JsonDocument.Parse(body).RootElement.Clone();
            var violations = Schemas.ValidateComponent("Problem", problem);
            Assert.True(violations.Count == 0, "Problem contract violated: " + Encoding.UTF8.GetString(body));
            code = problem.GetProperty("code").GetString();
        }
        return new FileAnswer(response.StatusCode, headers, body, code);
    }

    public sealed record FileAnswer(HttpStatusCode Status, IReadOnlyDictionary<string, string> Headers, byte[] Body, string? Code)
    {
        public string Text => Encoding.UTF8.GetString(Body);
    }

    public sealed record Answer(HttpStatusCode Status, JsonElement Body, string? ETag)
    {
        public static async Task<Answer> ReadAsync(HttpResponseMessage response, string? component)
        {
            var text = await response.Content.ReadAsStringAsync();
            var body = text.Length == 0 ? default : JsonDocument.Parse(text).RootElement.Clone();
            if (text.Length > 0)
            {
                var schema = (int)response.StatusCode >= 400 ? "Problem" : component;
                if (schema is not null)
                {
                    var violations = Schemas.ValidateComponent(schema, body);
                    Assert.True(violations.Count == 0,
                        $"{schema} contract violated: {string.Join("; ", violations.Select(v => v.InstanceLocation + " " + v.Message))}\n{text}");
                }
            }
            return new Answer(response.StatusCode, body, response.Headers.ETag?.Tag);
        }

        public string Code => Body.GetProperty("code").GetString()!;
    }
}
