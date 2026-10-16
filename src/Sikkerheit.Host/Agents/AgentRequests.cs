using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Agents;

/// <summary>The session of a request with a token: where the device belongs and which token it holds.</summary>
public sealed record AgentContext(Guid OrganizationId, Guid DeviceId);

public static class AgentVersions
{
    /// <summary>Compares major.minor.patch of two versions; a version that does not parse is the lowest.</summary>
    public static int Compare(string left, string right)
    {
        static (int, int, int)? Parse(string value)
        {
            var core = value.Split('-', '+')[0].Split('.');
            return core.Length == 3 && int.TryParse(core[0], NumberStyles.None, CultureInfo.InvariantCulture, out var a)
                && int.TryParse(core[1], NumberStyles.None, CultureInfo.InvariantCulture, out var b)
                && int.TryParse(core[2], NumberStyles.None, CultureInfo.InvariantCulture, out var c) ? (a, b, c) : null;
        }
        var x = Parse(left);
        var y = Parse(right);
        return (x, y) switch
        {
            (null, null) => 0,
            (null, _) => -1,
            (_, null) => 1,
            var (l, r) => l!.Value.CompareTo(r!.Value),
        };
    }
}

/// <summary>
/// Requests of an agent with a session token (05 «Регистрация и сессия»): the token, the status of the device and of the
/// organization are checked in the database on every request, without a cache; then check-in with the configuration.
/// </summary>
public static class AgentRequests
{
    public const int CheckInLimit = 4096;
    public static readonly TimeSpan ClockTolerance = TimeSpan.FromMinutes(5);

    public static void Map(IEndpointRouteBuilder agent)
    {
        agent.MapPost("/check-ins", CheckIn);
        agent.MapPost("/scans", ScanIntake.SubmitAsync);
    }

    /// <summary>The device of a Bearer token: 401 session_invalid, 401 device_revoked, 403 organization_inactive in this order.</summary>
    public static async Task<AgentContext> AuthenticateAsync(HttpContext http, DbScopes scopes, TimeProvider clock, CancellationToken ct)
    {
        var header = http.Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.Ordinal) || header.Length < 8)
        {
            throw new ApiProblemException(ProblemCodes.SessionInvalid);
        }
        var hash = AgentCrypto.Sha256Hex(header[7..].Trim());
        var now = clock.GetUtcNow();
        AgentSession session;
        await using (var platform = await scopes.PlatformAsync(ct))
        {
            session = await platform.Db.AgentSessions.AsNoTracking().SingleOrDefaultAsync(s => s.TokenHash == hash, ct)
                ?? throw new ApiProblemException(ProblemCodes.SessionInvalid);
        }
        if (session.ExpiresAt <= now)
        {
            throw new ApiProblemException(ProblemCodes.SessionInvalid);
        }
        await using var scope = await scopes.OrganizationAsync(session.OrganizationId, ct);
        var device = await Devices.FindAsync(scope, session.DeviceId, forUpdate: false, ct)
            ?? throw new ApiProblemException(ProblemCodes.SessionInvalid);
        RequireUsable(device, await OrganizationLifecycle.FindAsync(scope, forUpdate: false, ct));
        return new AgentContext(session.OrganizationId, session.DeviceId);
    }

    /// <summary>Status checks of every request with a token: the device is not revoked, the organization is active.</summary>
    public static void RequireUsable(Device device, Organization? organization)
    {
        if (device.Status == "revoked")
        {
            throw new ApiProblemException(ProblemCodes.DeviceRevoked);
        }
        if (organization is null)
        {
            throw new ApiProblemException(ProblemCodes.SessionInvalid);
        }
        if (organization.Status != "active")
        {
            throw new ApiProblemException(ProblemCodes.OrganizationInactive);
        }
    }

    private static async Task<IResult> CheckIn(HttpContext http, RequestBodies bodies, DbScopes scopes, AgentOptions options,
        TimeProvider clock, CancellationToken ct)
    {
        var context = await AuthenticateAsync(http, scopes, clock, ct);
        var request = await bodies.ReadAsync<JsonElement>(http, "CheckIn", CheckInLimit);
        var body = request.Json;
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(context.OrganizationId, ct);
        var device = await Devices.FindAsync(scope, context.DeviceId, forUpdate: true, ct)
            ?? throw new ApiProblemException(ProblemCodes.SessionInvalid);
        RequireUsable(device, await OrganizationLifecycle.FindAsync(scope, forUpdate: false, ct));

        var fingerprint = AgentCrypto.Sha256Hex(body.GetProperty("machineFingerprint").GetString()!);
        if (fingerprint != device.MachineFingerprintHash)
        {
            Devices.MarkConflict(device, "fingerprint", now, fingerprint, null, body.GetProperty("reportedDisplayName").GetString());
            AuditLog.Device(scope, device.Id, "device.identity_conflict", "device", device.Id.ToString(), http.TraceIdentifier);
            await scope.CommitAsync(ct);
            throw new ApiProblemException(ProblemCodes.IdentityConflict, "conflictKind=fingerprint");
        }
        Devices.RecoverIdentity(device, now);
        var observedAt = DateTimeOffset.Parse(body.GetProperty("observedAt").GetString()!, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        device.LastSeenAt = now;
        device.ClockStatus = (observedAt - now).Duration() > ClockTolerance ? "inconsistent" : "ok";
        device.AgentVersion = body.GetProperty("agentVersion").GetString();
        device.ConfigSchemaVersion = body.GetProperty("configSchemaVersion").GetInt32();
        device.Telemetry = Devices.Telemetry(body) ?? "{}";
        AgentMetrics.CheckIn(context.OrganizationId, device.Id, body, device.ClockStatus == "inconsistent");
        await Devices.MarkPresentAsync(scope, device.Id, now, ct);
        await DeviceSubjects.SeenAsync(scope, device.Id, now, ct);

        var policy = await Policies.CurrentAsync(scope, ct) ?? throw new InvalidOperationException("Organization has no policy revision");
        var pending = await PendingScanRequestAsync(scope, device.Id, now, ct);
        var configuration = Configuration(device, policy, options, Math.Min(device.ConfigSchemaVersion ?? 1, options.ConfigSchemaVersion),
            pending, now);
        await scope.CommitAsync(ct);
        return Results.Json(configuration, ApiJson.Options);
    }

    /// <summary>The unfinished request of a technician: delivered with this check-in; expired ones are closed.</summary>
    private static async Task<Guid?> PendingScanRequestAsync(DbScope scope, Guid deviceId, DateTimeOffset now, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var open = await scope.Db.ScanRequests.Where(r => r.OrganizationId == org && r.DeviceId == deviceId
            && (r.State == "requested" || r.State == "delivered")).ToListAsync(ct);
        foreach (var request in open.Where(r => r.ExpiresAt <= now))
        {
            request.State = "expired";
        }
        var live = open.FirstOrDefault(r => r.State is "requested" or "delivered");
        if (live is { State: "requested" })
        {
            live.State = "delivered";
        }
        return live?.Id;
    }

    /// <summary>The configuration of the schema version the agent asked for (05 «API агента»): no field beyond that schema.</summary>
    public static object Configuration(Device device, PolicyRevision policy, AgentOptions options, int schemaVersion, Guid? pending,
        DateTimeOffset now)
    {
        using var document = JsonDocument.Parse(policy.Configuration);
        var root = document.RootElement;
        var agent = root.GetProperty("agent");
        var active = root.GetProperty("activeCheckIds").EnumerateArray().Select(e => e.GetString()!)
            .Where(id => id.StartsWith("WIN-", StringComparison.Ordinal)).ToArray();
        return new
        {
            configSchemaVersion = schemaVersion, policyVersion = policy.Version, activeCheckIds = active,
            scanIntervalHours = agent.GetProperty("scanIntervalHours").GetInt32(),
            checkInIntervalHours = agent.GetProperty("checkInIntervalHours").GetInt32(),
            scanJitterMinutes = agent.GetProperty("scanJitterMinutes").GetInt32(),
            maxBatchBytes = AgentOptions.MaxBatchBytes, maxBufferBytes = AgentOptions.MaxBufferBytes,
            maxBufferDays = agent.GetProperty("maxBufferDays").GetInt32(), lastAcceptedSequence = device.LastAcceptedSequence,
            lastAcceptedCompletedAt = device.ProjectionCompletedAt, minimumAgentVersion = options.MinimumAgentVersion,
            pendingScanRequestId = pending, serverTime = now,
        };
    }
}
