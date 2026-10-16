using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sikkerheit.Host.Agents;

namespace Sikkerheit.IntegrationTests.Infrastructure;

/// <summary>
/// A Windows agent for the tests: its own P-256 key, the installation id and the machine fingerprint of the contract, the
/// signatures of 05 «Регистрация и сессия» and the batches of the example of the package. It speaks to the service only
/// over HTTP, as the agent of WP-09 does, and checks every answer against the contract.
/// </summary>
public sealed class FakeAgent : IDisposable
{
    public const string Volume = @"\\?\Volume{5f1c2c1e-8a8f-4b3e-9a51-3c1d2e4f6a7b}\";
    public const string DefaultVersion = "0.1.0";
    private readonly HttpClient _http;
    private readonly TimeProvider _clock;

    public FakeAgent(ApiFactory factory, string enrollmentKey, Guid? installationId = null, string displayName = "PC-ANNE",
        string smbiosUuid = "4C4C4544-0042-3510-8058-B4C04F4E3732", string machineGuid = "8C1F7A2E-3B4D-4E5F-9A6B-7C8D9E0F1A2B")
    {
        _http = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = false });
        _clock = factory.Clock;
        EnrollmentKey = enrollmentKey;
        InstallationId = installationId ?? Guid.NewGuid();
        DisplayName = displayName;
        Fingerprint = ComputeFingerprint(InstallationId, smbiosUuid, machineGuid);
        Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

    public string EnrollmentKey { get; set; }
    public Guid InstallationId { get; }
    public string DisplayName { get; set; }
    public string Fingerprint { get; set; }
    public ECDsa Key { get; set; }
    public Guid? DeviceId { get; set; }
    public string? Token { get; private set; }
    public long Sequence { get; set; }

    /// <summary>HMAC-SHA256: the key is the 16 bytes of the installationId in RFC 4122 order, the message is the lower-case UUID, 0x00 and MachineGuid.</summary>
    public static string ComputeFingerprint(Guid installationId, string smbiosUuid, string machineGuid)
    {
        var key = installationId.ToByteArray(bigEndian: true);
        var message = Encoding.UTF8.GetBytes(smbiosUuid.ToLowerInvariant() + "\0" + machineGuid.Trim('{', '}').ToLowerInvariant());
        return Convert.ToHexStringLower(HMACSHA256.HashData(key, message));
    }

    public (string X, string Y) Jwk(ECDsa? key = null)
    {
        var point = (key ?? Key).ExportParameters(false).Q;
        return (AgentCrypto.Base64Url(point.X!), AgentCrypto.Base64Url(point.Y!));
    }

    public string Thumbprint(ECDsa? key = null)
    {
        var (x, y) = Jwk(key);
        return AgentCrypto.Thumbprint(x, y);
    }

    public static string Sign(ECDsa key, string text) => AgentCrypto.Base64Url(
        key.SignData(Encoding.UTF8.GetBytes(text), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

    public void Dispose()
    {
        _http.Dispose();
        Key.Dispose();
    }

    /// <summary>The answer of a call: status, parsed body and the raw headers.</summary>
    public sealed record Reply(HttpStatusCode Status, JsonElement Body, IReadOnlyDictionary<string, string> Headers, string Text)
    {
        public string Code => Body.GetProperty("code").GetString()!;
        public string? Detail => Body.TryGetProperty("detail", out var detail) ? detail.GetString() : null;
    }

    public async Task<Reply> SendAsync(string path, string? body, string? component, Action<HttpRequestMessage>? configure = null,
        string contentType = "application/json", byte[]? bytes = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path);
        if (bytes is not null || body is not null)
        {
            request.Content = bytes is null ? new StringContent(body!, Encoding.UTF8) : new ByteArrayContent(bytes);
            request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
        }
        configure?.Invoke(request);
        using var response = await _http.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        var answer = await StaffClient.Answer.ReadAsync(response, component);
        var headers = response.Headers.NonValidated.Concat(response.Content.Headers.NonValidated)
            .ToDictionary(h => h.Key, h => string.Join(", ", h.Value), StringComparer.OrdinalIgnoreCase);
        return new Reply(response.StatusCode, answer.Body, headers, text);
    }

    public Task<Reply> ChallengeAsync(string purpose = "enroll", Guid? deviceId = null) =>
        SendAsync("/api/v1/agent/challenges",
            JsonSerializer.Serialize(purpose == "session" ? new { purpose, deviceId = deviceId ?? DeviceId } : (object)new { purpose }), "Challenge");

    public async Task<string> NonceAsync(string purpose = "enroll", Guid? deviceId = null)
    {
        var challenge = await ChallengeAsync(purpose, deviceId);
        Assert.Equal(HttpStatusCode.Created, challenge.Status);
        return challenge.Body.GetProperty("nonce").GetString()!;
    }

    public sealed record EnrollOptions
    {
        public Guid? RegistrationRequestId { get; init; }
        public string? Nonce { get; init; }
        public ECDsa? SigningKey { get; init; }
        public ECDsa? PublicKey { get; init; }
        public string? PreviousKeySignatureBy { get; init; }
        public ECDsa? PreviousKey { get; init; }
        public string? Key { get; init; }
        public string? KeyProtection { get; init; }
        public string? Authorization { get; init; }
        public Func<JsonObject, JsonObject>? Edit { get; init; }
    }

    /// <summary>The body of enrollAgent for the current key; the request is signed as the contract says.</summary>
    public async Task<(string Body, Guid RegistrationRequestId)> EnrollBodyAsync(EnrollOptions? options = null)
    {
        options ??= new EnrollOptions();
        var nonce = options.Nonce ?? await NonceAsync();
        var request = options.RegistrationRequestId ?? Guid.NewGuid();
        var publicKey = options.PublicKey ?? Key;
        var (x, y) = Jwk(publicKey);
        var protection = options.KeyProtection ?? "software";
        var signed = AgentCrypto.EnrollmentString(nonce, request, InstallationId, Fingerprint, protection, Thumbprint(publicKey));
        var body = new JsonObject
        {
            ["registrationRequestId"] = request.ToString(), ["installationId"] = InstallationId.ToString(), ["displayName"] = DisplayName,
            ["machineFingerprint"] = Fingerprint,
            ["publicKey"] = new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = x, ["y"] = y },
            ["keyProtection"] = protection, ["nonce"] = nonce, ["signature"] = Sign(options.SigningKey ?? publicKey, signed),
        };
        if (options.PreviousKey is not null)
        {
            body["previousKeySignature"] = Sign(options.PreviousKey, signed);
        }
        if (options.Edit is not null)
        {
            body = options.Edit(body);
        }
        return (body.ToJsonString(), request);
    }

    public async Task<Reply> EnrollAsync(EnrollOptions? options = null)
    {
        var (body, _) = await EnrollBodyAsync(options);
        return await EnrollRawAsync(body, options);
    }

    public Task<Reply> EnrollRawAsync(string body, EnrollOptions? options = null) =>
        SendAsync("/api/v1/agent/enrollments", body, "Enrollment", request =>
        {
            var authorization = options?.Authorization ?? "Enrollment " + (options?.Key ?? EnrollmentKey);
            request.Headers.TryAddWithoutValidation("Authorization", authorization);
        });

    /// <summary>Registers and remembers the deviceId; the registration must succeed.</summary>
    public async Task<Guid> EnrollOkAsync(EnrollOptions? options = null)
    {
        var reply = await EnrollAsync(options);
        Assert.Equal(HttpStatusCode.Created, reply.Status);
        DeviceId = Guid.Parse(reply.Body.GetProperty("deviceId").GetString()!);
        return DeviceId.Value;
    }

    public async Task<Reply> SessionAsync(string? nonce = null, ECDsa? signingKey = null, Guid? deviceId = null)
    {
        var id = deviceId ?? DeviceId!.Value;
        nonce ??= await NonceAsync("session", id);
        var body = new { deviceId = id, nonce, signature = Sign(signingKey ?? Key, AgentCrypto.SessionString(nonce, id)) };
        var reply = await SendAsync("/api/v1/agent/sessions", JsonSerializer.Serialize(body), "AgentSession");
        if (reply.Status == HttpStatusCode.Created)
        {
            Token = reply.Body.GetProperty("accessToken").GetString();
        }
        return reply;
    }

    public async Task StartSessionAsync()
    {
        var reply = await SessionAsync();
        Assert.Equal(HttpStatusCode.Created, reply.Status);
    }

    public Task<Reply> CheckInAsync(Func<JsonObject, JsonObject>? edit = null, string? token = null)
    {
        var body = new JsonObject
        {
            ["observedAt"] = Time(_clock.GetUtcNow()), ["agentVersion"] = DefaultVersion, ["configSchemaVersion"] = 1,
            ["machineFingerprint"] = Fingerprint, ["reportedDisplayName"] = DisplayName, ["queueDepth"] = 0, ["bufferBytes"] = 0,
            ["droppedBatchCount"] = 0, ["rejectedBatchCount"] = 0, ["configRejected"] = false, ["serviceStarts"] = 1,
            ["lastCrashAt"] = null, ["workingSetMb"] = 40, ["cpuSeconds"] = 2, ["abandonedCollectors"] = 0,
        };
        if (edit is not null)
        {
            body = edit(body);
        }
        return SendAsync("/api/v1/agent/check-ins", body.ToJsonString(), "Configuration", request =>
            request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + (token ?? Token)));
    }

    public static string Time(DateTimeOffset value) => value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// <summary>A full batch of the example of the package with the observations of the time, edited by the test.</summary>
    public JsonObject Batch(DateTimeOffset? completedAt = null, Action<JsonObject>? edit = null, long? sequence = null, int policyVersion = 1)
    {
        var end = completedAt ?? _clock.GetUtcNow().AddSeconds(-30);
        var seen = Time(end.AddSeconds(-30));
        JsonObject Observation(string check, JsonObject subject, JsonObject evidence) => new()
        {
            ["checkId"] = check, ["collectorVersion"] = DefaultVersion, ["subject"] = subject, ["observedAt"] = seen,
            ["collectionStatus"] = "collected", ["evidence"] = evidence,
        };
        JsonObject Volume_() => new() { ["type"] = "volume", ["volumeId"] = Volume, ["mountPoint"] = "C:", ["role"] = "os" };
        JsonObject Device() => new() { ["type"] = "device" };
        var batch = new JsonObject
        {
            ["schemaVersion"] = "2.0", ["scanId"] = Guid.NewGuid().ToString(), ["sequence"] = sequence ?? ++Sequence,
            ["agentVersion"] = DefaultVersion, ["policyVersion"] = policyVersion, ["machineFingerprint"] = Fingerprint,
            ["startedAt"] = Time(end.AddMinutes(-1)), ["completedAt"] = Time(end), ["scanRequestId"] = null,
            ["observations"] = new JsonArray
            {
                Observation("WIN-001", Volume_(), new JsonObject { ["totalBytes"] = 256_000_000_000, ["freeBytes"] = 90_000_000_000 }),
                Observation("WIN-002", Volume_(), new JsonObject
                    { ["volumeStatus"] = "fully_encrypted", ["protectionStatus"] = "on", ["encryptionPercentage"] = 100 }),
                Observation("WIN-003", Device(), new JsonObject
                {
                    ["products"] = new JsonArray(new JsonObject
                        { ["provider"] = "Microsoft Defender Antivirus", ["productState"] = "on", ["statusSource"] = "defender", ["rawState"] = null }),
                    ["defender"] = new JsonObject { ["amRunningMode"] = "normal", ["realTimeProtectionEnabled"] = true },
                }),
                Observation("WIN-004", Device(), new JsonObject { ["signatureLastUpdatedAt"] = Time(end.AddHours(-2)) }),
                Observation("WIN-005", Device(), new JsonObject
                    { ["domainEnabled"] = true, ["privateEnabled"] = true, ["publicEnabled"] = true, ["firewallProducts"] = new JsonArray() }),
                Observation("WIN-006", Device(), new JsonObject
                {
                    ["lastSearchSuccessAt"] = Time(end.AddHours(-5)), ["lastInstallSuccessAt"] = Time(end.AddHours(-9)), ["wsusConfigured"] = false,
                }),
                Observation("WIN-007", Device(), new JsonObject { ["rebootRequired"] = false, ["lastBootAt"] = Time(end.AddHours(-8)) }),
                Observation("WIN-008", Device(), new JsonObject
                {
                    ["members"] = new JsonArray(new JsonObject
                        { ["sid"] = "S-1-5-21-1000-2000-3000-500", ["kind"] = "builtin_administrator", ["relativeId"] = 500 }),
                    ["membershipScope"] = "direct_members",
                }),
                Observation("WIN-009", Device(), new JsonObject { ["enabled"] = true, ["platform"] = "uefi" }),
                Observation("WIN-010", Device(), new JsonObject
                {
                    ["joinType"] = "entra_joined", ["tenantId"] = "22222222-2222-4222-8222-222222222222",
                    ["entraDeviceId"] = "33333333-3333-4333-8333-333333333333",
                }),
                Observation("WIN-011", Device(), new JsonObject
                {
                    ["editionId"] = "Professional", ["displayVersion"] = "25H2", ["build"] = 26200, ["ubr"] = 9711, ["architecture"] = "x64",
                }),
            },
        };
        edit?.Invoke(batch);
        return batch;
    }

    public static JsonObject ObservationOf(JsonObject batch, string checkId) =>
        batch["observations"]!.AsArray().Select(o => o!.AsObject()).Single(o => o["checkId"]!.GetValue<string>() == checkId);

    public static void Remove(JsonObject batch, string checkId)
    {
        var observations = batch["observations"]!.AsArray();
        observations.Remove(observations.Single(o => o!["checkId"]!.GetValue<string>() == checkId));
    }

    public static void MakeUnavailable(JsonObject batch, string checkId, string reason)
    {
        var observation = ObservationOf(batch, checkId);
        observation.Remove("evidence");
        observation["collectionStatus"] = "unavailable";
        observation["reasonCode"] = reason;
    }

    public Task<Reply> SubmitAsync(JsonObject batch, DateTimeOffset? sentAt = null, string? token = null, string? idempotencyKey = null,
        Action<HttpRequestMessage>? configure = null) =>
        SubmitRawAsync(Encoding.UTF8.GetBytes(batch.ToJsonString()), batch["scanId"]!.GetValue<string>(), sentAt, token, idempotencyKey, configure);

    public Task<Reply> SubmitRawAsync(byte[] bytes, string scanId, DateTimeOffset? sentAt = null, string? token = null,
        string? idempotencyKey = null, Action<HttpRequestMessage>? configure = null, string contentType = "application/json") =>
        SendAsync("/api/v1/agent/scans", null, "ScanReceipt", request =>
        {
            request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + (token ?? Token));
            request.Headers.TryAddWithoutValidation("Idempotency-Key", idempotencyKey ?? scanId);
            request.Headers.TryAddWithoutValidation("Sikkerheit-Sent-At", Time(sentAt ?? _clock.GetUtcNow()));
            configure?.Invoke(request);
        }, contentType, bytes);
}
