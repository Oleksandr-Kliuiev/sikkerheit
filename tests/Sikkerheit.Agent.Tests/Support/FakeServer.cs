using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sikkerheit.Agent.Config;
using Sikkerheit.Agent.Protocol;
using Sikkerheit.Contracts;

namespace Sikkerheit.Agent.Tests;

/// <summary>A request that reached the fake server.</summary>
public sealed record SeenRequest(string Path, byte[] Body, IReadOnlyDictionary<string, string> Headers, int Status, string? Code)
{
    public JsonObject Json => JsonNode.Parse(Body)!.AsObject();
}

/// <summary>
/// The server of the agent API in memory (05, "API агента"): signs and nonces are really checked, bodies are validated by the schemas
/// of the OpenAPI document. Just enough of the order of checks of 05 for the agent tests; the real server is the business of WP-10.
/// </summary>
public sealed class FakeServer(Func<DateTimeOffset> clock) : HttpMessageHandler
{
    private static readonly ContractSchemas Schemas = new();
    private readonly byte[] _hmacKey = RandomNumberGenerator.GetBytes(32);
    private readonly HashSet<string> _usedNonces = [];
    private readonly Dictionary<string, FakeDevice> _devices = [];
    private readonly Dictionary<string, (string Hash, string Response)> _enrollments = [];
    private readonly Dictionary<string, Func<HttpRequestMessage, HttpResponseMessage?>> _scripts = [];
    private readonly Dictionary<string, (string Device, DateTimeOffset Expires)> _sessions = [];

    private readonly Dictionary<string, int> _lost = [];

    public List<SeenRequest> Requests { get; } = [];

    /// <summary>The server processes the next requests to the path, but the answer is lost (504 of the frontend).</summary>
    public void LoseResponses(string path, int count) => _lost[path] = count;

    public List<string> SchemaViolations { get; } = [];

    public HashSet<string> ValidKeys { get; } = [];

    public HashSet<string> RevokedKeys { get; } = [];

    public HashSet<string> RevokedInstallations { get; } = [];

    public bool OrganizationActive { get; set; } = true;

    public string MinimumAgentVersion { get; set; } = "0.1.0";

    public int PolicyVersion { get; set; } = 1;

    public string? PendingScanRequestId { get; set; }

    public JsonObject ConfigurationOverrides { get; } = [];

    public List<JsonObject> Accepted { get; } = [];

    public int SessionsCreated { get; private set; }

    public IReadOnlyDictionary<string, FakeDevice> Devices => _devices;

    public static string NewEnrollmentKey()
    {
        var key = "sikk_" + Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
        return key;
    }

    /// <summary>The database is restored to a point before the registration: the server does not know the devices.</summary>
    public void ForgetDevices()
    {
        _devices.Clear();
        _sessions.Clear();
    }

    /// <summary>The next request to the path is answered by the script (return null: the usual processing).</summary>
    public void Script(string path, Func<HttpRequestMessage, HttpResponseMessage?> script) => _scripts[path] = script;

    public void ClearScripts() => _scripts.Clear();

    public static HttpResponseMessage Problem(HttpStatusCode status, string code, string? retryAfter = null, string? minimum = null)
    {
        var body = new JsonObject
        {
            ["type"] = "https://contracts.sikkerheit.example.invalid/problems/" + code,
            ["title"] = code,
            ["status"] = (int)status,
            ["code"] = code,
            ["correlationId"] = Guid.NewGuid().ToString("N"),
        };
        if (minimum is not null)
        {
            body["minimumAgentVersion"] = minimum;
        }
        var response = Json(status, body);
        if (retryAfter is not null)
        {
            response.Headers.TryAddWithoutValidation("Retry-After", retryAfter);
        }
        return response;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        var path = request.RequestUri!.AbsolutePath;
        var headers = request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase);
        if (request.Content?.Headers.ContentType is { } type)
        {
            headers["Content-Type"] = type.ToString();
        }
        HttpResponseMessage response;
        if (_scripts.TryGetValue(path, out var script) && script(request) is { } scripted)
        {
            response = scripted;
        }
        else
        {
            response = Route(path, body, headers);
        }
        if (_lost.TryGetValue(path, out var left) && left > 0)
        {
            _lost[path] = left - 1;
            response = new HttpResponseMessage(HttpStatusCode.GatewayTimeout);
        }
        string? code = null;
        if ((int)response.StatusCode >= 400 && response.Content.Headers.ContentLength != 0 && response.Content is not null)
        {
            code = JsonNode.Parse(await response.Content.ReadAsStringAsync(cancellationToken))?["code"]?.GetValue<string>();
        }
        Requests.Add(new SeenRequest(path, body, headers, (int)response.StatusCode, code));
        return response;
    }

    private HttpResponseMessage Route(string path, byte[] body, Dictionary<string, string> headers)
    {
        switch (path)
        {
            case "/api/v1/agent/challenges":
                return Challenge(body);
            case "/api/v1/agent/enrollments":
                return Enroll(body, headers);
            case "/api/v1/agent/sessions":
                return Session(body);
            case "/api/v1/agent/check-ins":
                return Authorized(headers, body, CheckIn);
            case "/api/v1/agent/scans":
                return Authorized(headers, body, Scan);
            default:
                return Problem(HttpStatusCode.NotFound, "not_found");
        }
    }

    // ---- nonce ------------------------------------------------------------------------------------------------------------------

    private HttpResponseMessage Challenge(byte[] body)
    {
        if (body.Length > 1024)
        {
            return Problem(HttpStatusCode.RequestEntityTooLarge, "payload_too_large");
        }
        if (!TryParse(body, "ChallengeRequest", out var json, out var failure))
        {
            return failure!;
        }
        var purpose = json!["purpose"]!.GetValue<string>();
        var deviceId = json["deviceId"]?.GetValue<string>() ?? "";
        var random = RandomNumberGenerator.GetBytes(12);
        var expires = (uint)(clock().AddMinutes(5).ToUnixTimeSeconds());
        var nonce = new byte[32];
        random.CopyTo(nonce, 0);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(12), expires);
        Mac(random, expires, purpose, deviceId).CopyTo(nonce, 16);
        return Json(HttpStatusCode.Created, new JsonObject
        {
            ["nonce"] = Base64Url.Encode(nonce),
            ["expiresAt"] = FormatTime(clock().AddMinutes(5)),
        });
    }

    private byte[] Mac(byte[] random, uint expires, string purpose, string deviceId)
    {
        var data = Encoding.UTF8.GetBytes($"sikkerheit-nonce-v1\n{Convert.ToHexString(random)}\n{expires}\n{purpose}\n{deviceId}");
        return HMACSHA256.HashData(_hmacKey, data)[..16];
    }

    /// <summary>The nonce is known, not expired, not used and of this purpose (05); the nonce is used up.</summary>
    private bool RedeemNonce(string nonce, string purpose, string deviceId)
    {
        byte[] raw;
        try
        {
            raw = Base64Url.Decode(nonce);
        }
        catch (FormatException)
        {
            return false;
        }
        var random = raw[..12];
        var expires = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(12));
        if (!CryptographicOperations.FixedTimeEquals(raw.AsSpan(16), Mac(random, expires, purpose, deviceId))
            || expires < (uint)clock().ToUnixTimeSeconds())
        {
            return false;
        }
        return _usedNonces.Add(nonce);
    }

    // ---- registration -----------------------------------------------------------------------------------------------------------

    private HttpResponseMessage Enroll(byte[] body, Dictionary<string, string> headers)
    {
        if (body.Length > 16384)
        {
            return Problem(HttpStatusCode.RequestEntityTooLarge, "payload_too_large");
        }
        if (!TryParse(body, "EnrollmentRequest", out var json, out var failure))
        {
            return failure!;
        }
        var key = headers.GetValueOrDefault("Authorization")?.Replace("Enrollment ", "", StringComparison.Ordinal);
        if (key is null || (!ValidKeys.Contains(key) && !RevokedKeys.Contains(key)))
        {
            return Problem(HttpStatusCode.Unauthorized, "enrollment_key_invalid");
        }
        var requestId = json!["registrationRequestId"]!.GetValue<string>();
        var hash = Convert.ToHexString(SHA256.HashData(body));
        if (_enrollments.TryGetValue(requestId, out var earlier))
        {
            return earlier.Hash == hash
                ? Json(HttpStatusCode.Created, JsonNode.Parse(earlier.Response)!)
                : Problem(HttpStatusCode.Conflict, "idempotency_conflict");
        }
        if (RevokedKeys.Contains(key) || !ValidKeys.Contains(key))
        {
            return Problem(HttpStatusCode.Unauthorized, "enrollment_key_invalid");
        }
        if (!OrganizationActive)
        {
            return Problem(HttpStatusCode.Forbidden, "organization_inactive");
        }
        var installationId = json["installationId"]!.GetValue<string>();
        var publicKey = ToEcdsa(json["publicKey"]!);
        var jwk = new PublicKeyJwk(json["publicKey"]!["x"]!.GetValue<string>(), json["publicKey"]!["y"]!.GetValue<string>());
        var signed = SignedStrings.Enroll(json["nonce"]!.GetValue<string>(), requestId, installationId,
            json["machineFingerprint"]!.GetValue<string>(), json["keyProtection"]!.GetValue<string>(), jwk);
        if (!Verify(publicKey, signed, json["signature"]!.GetValue<string>()) || !RedeemNonce(json["nonce"]!.GetValue<string>(), "enroll", ""))
        {
            return Problem(HttpStatusCode.Unauthorized, "challenge_invalid");
        }
        var existing = _devices.Values.FirstOrDefault(d => d.InstallationId == installationId);
        if (RevokedInstallations.Contains(installationId) || existing is { Revoked: true })
        {
            return Problem(HttpStatusCode.Unauthorized, "device_revoked");
        }
        var reenrolled = false;
        if (existing is not null)
        {
            if (existing.Fingerprint != json["machineFingerprint"]!.GetValue<string>())
            {
                return Problem(HttpStatusCode.Conflict, "identity_conflict");
            }
            if (existing.Thumbprint != jwk.Thumbprint())
            {
                var previous = json["previousKeySignature"]?.GetValue<string>();
                if (previous is null || !Verify(existing.Key, signed, previous))
                {
                    existing.RejectedKey = jwk;
                    return Problem(HttpStatusCode.Conflict, "identity_conflict");
                }
                existing.Replace(publicKey, jwk);
                foreach (var token in _sessions.Where(s => s.Value.Device == existing.DeviceId).Select(s => s.Key).ToList())
                {
                    _sessions.Remove(token);
                }
            }
            reenrolled = true;
        }
        else
        {
            existing = new FakeDevice(Guid.NewGuid().ToString("D"), installationId, json["machineFingerprint"]!.GetValue<string>(), publicKey, jwk);
            _devices[existing.DeviceId] = existing;
        }
        var response = new JsonObject
        {
            ["deviceId"] = existing.DeviceId,
            ["enrolledAt"] = FormatTime(clock()),
            ["reenrolled"] = reenrolled,
        };
        _enrollments[requestId] = (hash, response.ToJsonString());
        return Json(HttpStatusCode.Created, response);
    }

    private HttpResponseMessage Session(byte[] body)
    {
        if (body.Length > 1024)
        {
            return Problem(HttpStatusCode.RequestEntityTooLarge, "payload_too_large");
        }
        if (!TryParse(body, "SessionRequest", out var json, out var failure))
        {
            return failure!;
        }
        var deviceId = json!["deviceId"]!.GetValue<string>();
        if (!_devices.TryGetValue(deviceId, out var device))
        {
            return Problem(HttpStatusCode.Unauthorized, "device_unknown");
        }
        if (device.Revoked)
        {
            return Problem(HttpStatusCode.Unauthorized, "device_revoked");
        }
        var nonce = json["nonce"]!.GetValue<string>();
        if (!Verify(device.Key, SignedStrings.Session(nonce, deviceId), json["signature"]!.GetValue<string>())
            || !RedeemNonce(nonce, "session", deviceId))
        {
            return Problem(HttpStatusCode.Unauthorized, "challenge_invalid");
        }
        if (!OrganizationActive)
        {
            return Problem(HttpStatusCode.Forbidden, "organization_inactive");
        }
        var token = Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
        var expires = clock().AddMinutes(60);
        _sessions[token] = (deviceId, expires);
        SessionsCreated++;
        return Json(HttpStatusCode.Created, new JsonObject { ["accessToken"] = token, ["expiresAt"] = FormatTime(expires) });
    }

    // ---- requests with a token --------------------------------------------------------------------------------------------------

    private HttpResponseMessage Authorized(Dictionary<string, string> headers, byte[] body, Func<FakeDevice, byte[], Dictionary<string, string>, HttpResponseMessage> handler)
    {
        var token = headers.GetValueOrDefault("Authorization")?.Replace("Bearer ", "", StringComparison.Ordinal);
        if (token is null || !_sessions.TryGetValue(token, out var session) || session.Expires <= clock())
        {
            return Problem(HttpStatusCode.Unauthorized, "session_invalid");
        }
        var device = _devices[session.Device];
        if (device.Revoked)
        {
            return Problem(HttpStatusCode.Unauthorized, "device_revoked");
        }
        return OrganizationActive ? handler(device, body, headers) : Problem(HttpStatusCode.Forbidden, "organization_inactive");
    }

    private HttpResponseMessage CheckIn(FakeDevice device, byte[] body, Dictionary<string, string> headers)
    {
        if (body.Length > 4096)
        {
            return Problem(HttpStatusCode.RequestEntityTooLarge, "payload_too_large");
        }
        if (!TryParse(body, "CheckIn", out var json, out var failure))
        {
            return failure!;
        }
        if (json!["machineFingerprint"]!.GetValue<string>() != device.Fingerprint)
        {
            return Problem(HttpStatusCode.Conflict, "identity_conflict");
        }
        device.LastCheckIn = json;
        var configuration = new JsonObject
        {
            ["configSchemaVersion"] = json["configSchemaVersion"]!.GetValue<int>(),
            ["policyVersion"] = PolicyVersion,
            ["activeCheckIds"] = new JsonArray([.. StubCollectors.CheckIds.Select(id => (JsonNode)id)]),
            ["scanIntervalHours"] = 24,
            ["checkInIntervalHours"] = 4,
            ["scanJitterMinutes"] = 0,
            ["maxBatchBytes"] = 262144,
            ["maxBufferBytes"] = 104857600,
            ["maxBufferDays"] = 7,
            ["lastAcceptedSequence"] = device.LastAcceptedSequence,
            ["lastAcceptedCompletedAt"] = device.LastAcceptedCompletedAt is null ? null : FormatTime(device.LastAcceptedCompletedAt.Value),
            ["minimumAgentVersion"] = MinimumAgentVersion,
            ["pendingScanRequestId"] = PendingScanRequestId,
            ["serverTime"] = FormatTime(clock()),
        };
        foreach (var (name, value) in ConfigurationOverrides)
        {
            configuration[name] = value?.DeepClone();
        }
        return Json(HttpStatusCode.OK, configuration);
    }

    private HttpResponseMessage Scan(FakeDevice device, byte[] body, Dictionary<string, string> headers)
    {
        if (!headers.GetValueOrDefault("Content-Type", "").StartsWith("application/json", StringComparison.Ordinal)
            || headers.ContainsKey("Content-Encoding"))
        {
            return Problem(HttpStatusCode.UnsupportedMediaType, "unsupported_media_type");
        }
        if (body.Length > 262144)
        {
            return Problem(HttpStatusCode.RequestEntityTooLarge, "payload_too_large");
        }
        JsonObject json;
        try
        {
            json = JsonNode.Parse(body)!.AsObject();
        }
        catch (JsonException)
        {
            return Problem(HttpStatusCode.BadRequest, "invalid_json");
        }
        if (AgentVersion.Compare(json["agentVersion"]?.GetValue<string>() ?? "0.0.0", MinimumAgentVersion) < 0)
        {
            return Problem(HttpStatusCode.UnprocessableEntity, "agent_version_unsupported", minimum: MinimumAgentVersion);
        }
        if (json["schemaVersion"]?.GetValue<string>() != "2.0")
        {
            return Problem(HttpStatusCode.UnprocessableEntity, "unsupported_schema_version");
        }
        using (var document = JsonDocument.Parse(body))
        {
            var violations = Schemas.ValidateStandalone("scan-batch.schema.json", document.RootElement);
            if (violations.Count > 0 || !headers.ContainsKey("Sikkerheit-Sent-At") || !headers.ContainsKey("Idempotency-Key"))
            {
                SchemaViolations.AddRange(violations.Select(v => $"scan: {v.InstanceLocation} {v.Message}"));
                return Problem(HttpStatusCode.UnprocessableEntity, "schema_violation");
            }
        }
        var scanId = json["scanId"]!.GetValue<string>();
        var hash = Convert.ToHexString(SHA256.HashData(body));
        if (device.Scans.TryGetValue(scanId, out var earlier))
        {
            return earlier.Hash == hash
                ? Json(HttpStatusCode.OK, Receipt(scanId, earlier.Sequence, duplicate: true, false))
                : Problem(HttpStatusCode.Conflict, "idempotency_conflict");
        }
        if (json["machineFingerprint"]!.GetValue<string>() != device.Fingerprint)
        {
            return Problem(HttpStatusCode.Conflict, "identity_conflict");
        }
        var sequence = json["sequence"]!.GetValue<long>();
        if (sequence <= device.LastAcceptedSequence)
        {
            return Problem(HttpStatusCode.Conflict, "sequence_conflict");
        }
        if (json["policyVersion"]!.GetValue<int>() > PolicyVersion)
        {
            return Problem(HttpStatusCode.UnprocessableEntity, "unknown_policy_version");
        }
        device.Scans[scanId] = (hash, sequence);
        device.LastAcceptedSequence = sequence;
        device.LastAcceptedCompletedAt = DateTimeOffset.Parse(json["completedAt"]!.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal);
        Accepted.Add(json);
        if (json["scanRequestId"]?.GetValue<string>() == PendingScanRequestId)
        {
            PendingScanRequestId = null;
        }
        return Json(HttpStatusCode.OK, Receipt(scanId, sequence, false, false));
    }

    private JsonObject Receipt(string scanId, long sequence, bool duplicate, bool clockInconsistent) => new()
    {
        ["scanId"] = scanId,
        ["sequence"] = sequence,
        ["acceptedAt"] = FormatTime(clock()),
        ["duplicate"] = duplicate,
        ["clockInconsistent"] = clockInconsistent,
    };

    // ---- helpers ----------------------------------------------------------------------------------------------------------------

    private bool TryParse(byte[] body, string component, out JsonObject? json, out HttpResponseMessage? failure)
    {
        json = null;
        failure = null;
        try
        {
            json = JsonNode.Parse(body)!.AsObject();
        }
        catch (JsonException)
        {
            failure = Problem(HttpStatusCode.BadRequest, "invalid_json");
            return false;
        }
        using var document = JsonDocument.Parse(body);
        var violations = Schemas.ValidateComponent(component, document.RootElement);
        if (violations.Count > 0)
        {
            SchemaViolations.AddRange(violations.Select(v => $"{component}: {v.InstanceLocation} {v.Message}"));
            failure = Problem(HttpStatusCode.UnprocessableEntity, "schema_violation");
            return false;
        }
        return true;
    }

    private static ECDsa ToEcdsa(JsonNode jwk)
    {
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = Base64Url.Decode(jwk["x"]!.GetValue<string>()), Y = Base64Url.Decode(jwk["y"]!.GetValue<string>()) },
        };
        return ECDsa.Create(parameters);
    }

    private static bool Verify(ECDsa key, byte[] data, string signature)
    {
        try
        {
            return key.VerifyData(data, Base64Url.Decode(signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException or ArgumentException)
        {
            return false;
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode status, JsonNode body) => new(status)
    {
        Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
    };

    public static string FormatTime(DateTimeOffset value) => value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
}

/// <summary>A device registered on the fake server.</summary>
public sealed class FakeDevice(string deviceId, string installationId, string fingerprint, ECDsa key, PublicKeyJwk jwk)
{
    public string DeviceId { get; } = deviceId;

    public string InstallationId { get; } = installationId;

    public string Fingerprint { get; set; } = fingerprint;

    public ECDsa Key { get; private set; } = key;

    public string Thumbprint { get; private set; } = jwk.Thumbprint();

    public PublicKeyJwk? RejectedKey { get; set; }

    public bool Revoked { get; set; }

    public long LastAcceptedSequence { get; set; }

    public DateTimeOffset? LastAcceptedCompletedAt { get; set; }

    public Dictionary<string, (string Hash, long Sequence)> Scans { get; } = [];

    public JsonObject? LastCheckIn { get; set; }

    public void Replace(ECDsa newKey, PublicKeyJwk newJwk)
    {
        Key = newKey;
        Thumbprint = newJwk.Thumbprint();
    }
}
