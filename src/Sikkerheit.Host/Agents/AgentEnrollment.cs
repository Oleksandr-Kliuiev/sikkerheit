using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Agents;

public sealed record ChallengeRequestBody(string Purpose, Guid? DeviceId);

public sealed record PublicKeyBody(string Kty, string Crv, string X, string Y);

public sealed record EnrollmentBody(
    Guid RegistrationRequestId, Guid InstallationId, string DisplayName, string MachineFingerprint, PublicKeyBody PublicKey,
    string KeyProtection, string Nonce, string Signature, string? PreviousKeySignature);

public sealed record SessionBody(Guid DeviceId, string Nonce, string Signature);

/// <summary>
/// Challenge, registration and session of the agent (05 «Регистрация и сессия»). Anonymous operations are counted against
/// the rate limits; the checks of every operation run in the order of the table of 05, and the first that fails answers.
/// </summary>
public static class AgentEnrollment
{
    public const int EnrollLimit = 16384;
    public const int SmallLimit = 1024;
    public static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(60);
    private const string EnrollmentScheme = "Enrollment ";

    public static void Map(IEndpointRouteBuilder agent)
    {
        agent.MapPost("/challenges", CreateChallenge);
        agent.MapPost("/enrollments", Enroll);
        agent.MapPost("/sessions", CreateSession);
    }

    private static async Task<IResult> CreateChallenge(HttpContext http, RequestBodies bodies, Nonces nonces, AgentLimits limits,
        CancellationToken ct)
    {
        limits.HitAnonymous(http);
        var body = (await bodies.ReadAsync<ChallengeRequestBody>(http, "ChallengeRequest", SmallLimit)).Value;
        var (nonce, expiresAt) = nonces.Create(body.Purpose, body.Purpose == "session" ? body.DeviceId : null);
        return Results.Json(new { nonce, expiresAt }, ApiJson.Options, statusCode: StatusCodes.Status201Created);
    }

    /// <summary>Records the nonce as spent; false when it was spent before (unique nonce_hash).</summary>
    public static async Task<bool> RedeemAsync(DbScope scope, string nonce, string purpose, Guid? deviceId, DateTimeOffset expiresAt,
        DateTimeOffset now, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            insert into agent_challenge (nonce_hash, purpose, device_id, expires_at, used_at)
            values (@hash, @purpose, @device, @expires, @now) on conflict do nothing
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("hash", AgentCrypto.Sha256Hex(nonce));
        command.Parameters.AddWithValue("purpose", purpose);
        command.Parameters.AddWithValue("device", NpgsqlTypes.NpgsqlDbType.Uuid, (object?)deviceId ?? DBNull.Value);
        command.Parameters.AddWithValue("expires", expiresAt);
        command.Parameters.AddWithValue("now", now);
        return await command.ExecuteNonQueryAsync(ct) == 1;
    }

    private static string? KeyFromHeader(HttpContext http)
    {
        var header = http.Request.Headers.Authorization.ToString();
        return header.StartsWith(EnrollmentScheme, StringComparison.Ordinal) && header.Length > EnrollmentScheme.Length
            ? header[EnrollmentScheme.Length..].Trim()
            : null;
    }

    private static async Task<IResult> Enroll(HttpContext http, RequestBodies bodies, DbScopes scopes, Nonces nonces,
        AgentLimits limits, TimeProvider clock, CancellationToken ct)
    {
        limits.HitAnonymous(http);
        // 1. Size, JSON, schema.
        var request = await bodies.ReadAsync<EnrollmentBody>(http, "EnrollmentRequest", EnrollLimit);
        var body = request.Value;
        var now = clock.GetUtcNow();

        // 2. The key is known; a revoked key is still accepted for a repeat.
        var secret = KeyFromHeader(http) ?? throw new ApiProblemException(ProblemCodes.EnrollmentKeyInvalid);
        var hash = AgentCrypto.Sha256Hex(secret);
        var (organizationId, keyId) = await EnrollmentKeys.OwnerAsync(scopes, hash, ct)
            ?? throw new ApiProblemException(ProblemCodes.EnrollmentKeyInvalid);
        limits.HitRegistration(hash);

        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var key = await EnrollmentKeys.FindAsync(scope, keyId, ct) ?? throw new ApiProblemException(ProblemCodes.EnrollmentKeyInvalid);

        // 3. A repeat of the same registration request, checked before the status of the key.
        var org = organizationId;
        var previous = await scope.Db.Enrollments.AsNoTracking().SingleOrDefaultAsync(
            e => e.OrganizationId == org && e.RegistrationRequestId == body.RegistrationRequestId, ct);
        if (previous is not null && previous.CreatedAt + Idempotency.Window > now)
        {
            if (previous.RequestHash != request.RawHash)
            {
                throw new ApiProblemException(ProblemCodes.IdempotencyConflict);
            }
            return Results.Text(previous.Response, "application/json", statusCode: StatusCodes.Status201Created);
        }
        if (previous is not null)
        {
            // Past the 24 hours: the request id may be used again.
            await scope.Db.Enrollments.Where(e => e.OrganizationId == org && e.Id == previous.Id).ExecuteDeleteAsync(ct);
        }

        // 4. The key is revoked. 5. The organization is not active.
        if (key.RevokedAt is not null)
        {
            throw new ApiProblemException(ProblemCodes.EnrollmentKeyInvalid);
        }
        var organization = await OrganizationLifecycle.FindAsync(scope, forUpdate: false, ct)
            ?? throw new ApiProblemException(ProblemCodes.EnrollmentKeyInvalid);
        if (organization.Status != "active")
        {
            throw new ApiProblemException(ProblemCodes.OrganizationInactive);
        }

        // 6. The nonce is genuine, for registration, unspent; the signature is the new key's.
        using var publicKey = AgentCrypto.ImportPublicKey(body.PublicKey.X, body.PublicKey.Y)
            ?? throw new ApiProblemException(ProblemCodes.ChallengeInvalid);
        var thumbprint = AgentCrypto.Thumbprint(body.PublicKey.X, body.PublicKey.Y);
        // The agent signs the values as it sent them (the schema allows either case of the hex digits of a UUID).
        var signed = AgentCrypto.EnrollmentString(body.Nonce, request.Json.GetProperty("registrationRequestId").GetString()!,
            request.Json.GetProperty("installationId").GetString()!, body.MachineFingerprint, body.KeyProtection, thumbprint);
        var expires = nonces.Check(body.Nonce, "enroll", null);
        if (expires is null || !AgentCrypto.Verify(publicKey, signed, body.Signature))
        {
            throw new ApiProblemException(ProblemCodes.ChallengeInvalid);
        }

        // 7–10 under the lock of the installation: two clones registering at once create one device.
        await using (var lockCommand = new NpgsqlCommand("select pg_advisory_xact_lock(hashtextextended(@key, 0))",
                         scope.Connection, scope.Transaction))
        {
            lockCommand.Parameters.AddWithValue("key", organizationId.ToString("N") + ":" + body.InstallationId.ToString("N"));
            await lockCommand.ExecuteScalarAsync(ct);
        }
        if (!await RedeemAsync(scope, body.Nonce, "enroll", null, expires.Value, now, ct))
        {
            throw new ApiProblemException(ProblemCodes.ChallengeInvalid);
        }
        var fingerprint = AgentCrypto.Sha256Hex(body.MachineFingerprint);
        var jwk = AgentCrypto.CanonicalJwk(body.PublicKey.X, body.PublicKey.Y);
        var installation = body.InstallationId;
        var revoked = await scope.Db.RevokedInstallations.AsNoTracking().AnyAsync(
            r => r.OrganizationId == org && r.InstallationId == installation, ct);
        var device = await scope.Db.Devices.FromSqlInterpolated(
                $"select * from device where organization_id = {org} and installation_id = {installation} for update")
            .SingleOrDefaultAsync(ct);
        if (revoked || device is { Status: "revoked" })
        {
            throw new ApiProblemException(ProblemCodes.DeviceRevoked);
        }
        var reenrolled = false;
        string? conflict = null;
        if (device is null)
        {
            device = new Device
            {
                OrganizationId = org, Id = Guid.CreateVersion7(), DisplayName = body.DisplayName, InstallationId = installation,
                MachineFingerprintHash = fingerprint, PublicKeyJwk = jwk, KeyThumbprint = thumbprint,
                KeyProtection = body.KeyProtection, EnrollmentKeyId = keyId, EnrolledAt = now,
            };
            scope.Db.Devices.Add(device);
            await DeviceSubjects.EnsureAsync(scope, device.Id, device.DisplayName, now, ct);
            AuditLog.Device(scope, device.Id, "device.enroll", "device", device.Id.ToString(), http.TraceIdentifier);
        }
        else if (device.MachineFingerprintHash != fingerprint)
        {
            // 8. The machine is another one: the key stays, the conflict is kept for the technician (RB-11).
            Devices.MarkConflict(device, "fingerprint", now, fingerprint, null, body.DisplayName);
            AuditLog.Device(scope, device.Id, "device.identity_conflict", "device", device.Id.ToString(), http.TraceIdentifier);
            conflict = "conflictKind=fingerprint";
        }
        else if (device.KeyThumbprint == thumbprint)
        {
            reenrolled = true;
            device.KeyProtection = body.KeyProtection;
        }
        else if (body.PreviousKeySignature is { } previousSignature && SignedByStoredKey(device, signed, previousSignature))
        {
            ReplaceKey(device, jwk, thumbprint, body.KeyProtection);
            await Devices.DeleteSessionsAsync(scope, device.Id, ct);
            AuditLog.Device(scope, device.Id, "device.key_replaced", "device", device.Id.ToString(), http.TraceIdentifier);
            reenrolled = true;
        }
        else
        {
            Devices.MarkConflict(device, "key", now, null, jwk, body.DisplayName);
            AuditLog.Device(scope, device.Id, "device.identity_conflict", "device", device.Id.ToString(), http.TraceIdentifier);
            conflict = "conflictKind=key";
        }
        if (conflict is not null)
        {
            await scope.CommitAsync(ct);
            throw new ApiProblemException(ProblemCodes.IdentityConflict, conflict);
        }

        var response = new { deviceId = device.Id, enrolledAt = device.EnrolledAt, reenrolled };
        var json = ApiJson.Serialize(response);
        scope.Db.Enrollments.Add(new Enrollment
        {
            OrganizationId = org, Id = Guid.CreateVersion7(), RegistrationRequestId = body.RegistrationRequestId,
            EnrollmentKeyId = keyId, DeviceId = device.Id, RequestHash = request.RawHash, Response = json, CreatedAt = now,
        });
        key.LastUsedAt = now;
        try
        {
            await scope.CommitAsync(ct);
        }
        catch (DbUpdateException error) when (error.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation } unique)
        {
            throw new ApiProblemException(unique.ConstraintName?.Contains("thumbprint", StringComparison.Ordinal) == true
                ? ProblemCodes.IdentityConflict
                : ProblemCodes.IdempotencyConflict);
        }
        return Results.Text(json, "application/json", statusCode: StatusCodes.Status201Created);
    }

    /// <summary>The same signed string signed by the key the server holds for the device (a planned key change).</summary>
    private static bool SignedByStoredKey(Device device, string signed, string signature)
    {
        var (x, y) = AgentCrypto.ParseJwk(device.PublicKeyJwk);
        using var stored = AgentCrypto.ImportPublicKey(x, y);
        return stored is not null && AgentCrypto.Verify(stored, signed, signature);
    }

    /// <summary>Takes the new key; the caller removes the sessions of the device (05: every replacement does).</summary>
    public static void ReplaceKey(Device device, string jwk, string thumbprint, string keyProtection)
    {
        device.PublicKeyJwk = jwk;
        device.KeyThumbprint = thumbprint;
        device.KeyProtection = keyProtection;
    }

    private static async Task<IResult> CreateSession(HttpContext http, RequestBodies bodies, DbScopes scopes, Nonces nonces,
        AgentLimits limits, TimeProvider clock, CancellationToken ct)
    {
        limits.HitAnonymous(http);
        var sessionRequest = await bodies.ReadAsync<SessionBody>(http, "SessionRequest", SmallLimit);
        var body = sessionRequest.Value;
        var rawDeviceId = sessionRequest.Json.GetProperty("deviceId").GetString()!;
        var now = clock.GetUtcNow();

        // 1. The device is known (the lookup by deviceId alone returns only the organization).
        Guid? owner;
        await using (var platform = await scopes.PlatformAsync(ct))
        {
            owner = await platform.Db.Database.SqlQuery<Guid?>($"select app.device_owner({body.DeviceId}) as \"Value\"").SingleAsync(ct);
        }
        if (owner is not { } organizationId)
        {
            throw new ApiProblemException(ProblemCodes.DeviceUnknown);
        }
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var device = await Devices.FindAsync(scope, body.DeviceId, forUpdate: false, ct)
            ?? throw new ApiProblemException(ProblemCodes.DeviceUnknown);
        // 2. Revoked.
        if (device.Status == "revoked")
        {
            throw new ApiProblemException(ProblemCodes.DeviceRevoked);
        }
        // 3. Nonce and the signature of the stored key.
        var (x, y) = AgentCrypto.ParseJwk(device.PublicKeyJwk);
        using var stored = AgentCrypto.ImportPublicKey(x, y);
        var expires = nonces.Check(body.Nonce, "session", body.DeviceId);
        if (stored is null || expires is null
            || !AgentCrypto.Verify(stored, AgentCrypto.SessionString(body.Nonce, rawDeviceId), body.Signature)
            || !await RedeemAsync(scope, body.Nonce, "session", body.DeviceId, expires.Value, now, ct))
        {
            throw new ApiProblemException(ProblemCodes.ChallengeInvalid);
        }
        // 4. The organization is active.
        var organization = await OrganizationLifecycle.FindAsync(scope, forUpdate: false, ct)
            ?? throw new ApiProblemException(ProblemCodes.DeviceUnknown);
        if (organization.Status != "active")
        {
            throw new ApiProblemException(ProblemCodes.OrganizationInactive);
        }
        // 5. A token: 32 random bytes, stored as SHA-256, valid for 60 minutes.
        var token = AgentCrypto.Base64Url(RandomNumberGenerator.GetBytes(32));
        var expiresAt = now + SessionLifetime;
        scope.Db.AgentSessions.Add(new AgentSession
        {
            TokenHash = AgentCrypto.Sha256Hex(token), OrganizationId = organizationId, DeviceId = device.Id, ExpiresAt = expiresAt,
        });
        await scope.CommitAsync(ct);
        return Results.Json(new { accessToken = token, expiresAt }, ApiJson.Options, statusCode: StatusCodes.Status201Created);
    }
}
