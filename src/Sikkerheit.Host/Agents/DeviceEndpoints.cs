using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Agents;

public sealed record DeviceUpdateBody(string DisplayName);

public sealed record IdentityResolutionBody(string Decision);

public sealed record ScanRequestCreateBody(Guid IdempotencyKey, string Reason);

public sealed record ScanRequestDto(Guid Id, string State, DateTimeOffset ExpiresAt)
{
    public static ScanRequestDto From(ScanRequest r) => new(r.Id, r.State, r.ExpiresAt);
}

/// <summary>Devices in the portal (FR-09, FR-10; 05 «API портала»): list, name, revocation, identity decisions, rescans.</summary>
public static class DeviceEndpoints
{
    public static readonly TimeSpan ScanRequestLifetime = TimeSpan.FromHours(24);

    public static void Map(IEndpointRouteBuilder org)
    {
        org.MapGet("/devices", List).RequireStaff(StaffRoles.All);
        org.MapPatch("/devices/{deviceId:guid}", Update).RequireStaff(StaffRoles.AdminOnly);
        org.MapPost("/devices/{deviceId:guid}/revoke", Revoke).RequireStaff(StaffRoles.AdminOnly);
        org.MapPost("/devices/{deviceId:guid}/identity-resolutions", Resolve).RequireStaff(StaffRoles.AdminOnly);
        org.MapPost("/devices/{deviceId:guid}/scan-requests", RequestScan).RequireStaff(StaffRoles.Work);
    }

    private static async Task<IResult> List(Guid organizationId, DbScopes scopes, Cursors cursors, TimeProvider clock, string? cursor,
        string? limit, Guid? enrollmentKeyId, string? status, CancellationToken ct)
    {
        var size = OrganizationEndpoints.Limit(limit);
        if (status is not null and not ("active" or "revoked"))
        {
            throw new ApiProblemException(ProblemCodes.SchemaViolation, "status must be active or revoked");
        }
        var filter = Cursors.Filter(("enrollmentKeyId", enrollmentKeyId?.ToString()), ("status", status));
        var position = cursors.Read(cursor, "listDevices", organizationId, filter);
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        var query = scope.Db.Devices.AsNoTracking().Where(d => d.OrganizationId == organizationId);
        if (enrollmentKeyId is { } keyId)
        {
            query = query.Where(d => d.EnrollmentKeyId == keyId);
        }
        if (status is not null)
        {
            query = query.Where(d => d.Status == status);
        }
        if (position is not null)
        {
            var after = Guid.Parse(position[0]);
            query = query.Where(d => d.Id.CompareTo(after) > 0);
        }
        var rows = await query.OrderBy(d => d.Id).Take(size + 1).ToListAsync(ct);
        string? next = null;
        if (rows.Count > size)
        {
            rows.RemoveAt(size);
            next = cursors.Create("listDevices", organizationId, filter, [rows[^1].Id.ToString()]);
        }
        var now = clock.GetUtcNow();
        return Results.Json(new Page<DeviceDto>(rows.Select(d => DeviceDto.From(d, now)).ToList(), next), ApiJson.Options);
    }

    private static async Task<Device> RequireDeviceAsync(DbScope scope, Guid deviceId, bool forUpdate, CancellationToken ct) =>
        await Devices.FindAsync(scope, deviceId, forUpdate, ct) ?? throw new ApiProblemException(ProblemCodes.NotFound);

    private static async Task<IResult> Update(Guid organizationId, Guid deviceId, HttpContext http, RequestBodies bodies,
        DbScopes scopes, TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var body = (await bodies.ReadAsync<DeviceUpdateBody>(http, "DeviceUpdate")).Value;
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var organization = await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        OrganizationEndpoints.RequireActive(organization);
        var device = await RequireDeviceAsync(scope, deviceId, forUpdate: true, ct);
        device.DisplayName = body.DisplayName;
        await DeviceSubjects.RenameAsync(scope, deviceId, body.DisplayName, ct);
        AuditLog.Staff(scope, actor, "device.update", "device", deviceId.ToString(), http.TraceIdentifier);
        await scope.CommitAsync(ct);
        return Results.Json(DeviceDto.From(device, clock.GetUtcNow()), ApiJson.Options);
    }

    private static async Task<IResult> Revoke(Guid organizationId, Guid deviceId, HttpContext http, DbScopes scopes,
        ISecurityLog securityLog, TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        var device = await RequireDeviceAsync(scope, deviceId, forUpdate: true, ct);
        if (device.Status != "revoked")
        {
            // The record comes first: without it the device keeps working and the call answers 503 (04 «Отзыв и повторная регистрация»).
            await SecurityRecords.AppendAsync(http, securityLog, new SecurityLogRecord(Guid.CreateVersion7(), "device.revoke",
                organizationId, "device", deviceId.ToString(), now, http.TraceIdentifier, actor.EntraUserId,
                InstallationId: device.InstallationId, KeyThumbprint: device.KeyThumbprint, EnrollmentKeyId: device.EnrollmentKeyId), ct);
            MarkRevoked(device, now);
            scope.Db.RevokedInstallations.Add(new RevokedInstallation
            {
                OrganizationId = organizationId, InstallationId = device.InstallationId, KeyThumbprint = device.KeyThumbprint,
                DeviceId = deviceId, RevokedAt = now, Source = "revoke",
            });
            await DeviceSubjects.RetireAsync(scope, [deviceId], "manual_action", actor.EntraUserId, now, ct);
            AuditLog.Staff(scope, actor, "device.revoke", "device", deviceId.ToString(), http.TraceIdentifier);
        }
        await scope.CommitAsync(ct);
        return Results.NoContent();
    }

    public static void MarkRevoked(Device device, DateTimeOffset at)
    {
        device.Status = "revoked";
        device.RevokedAt = at;
    }

    private static async Task<IResult> Resolve(Guid organizationId, Guid deviceId, HttpContext http, RequestBodies bodies,
        DbScopes scopes, TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var body = (await bodies.ReadAsync<IdentityResolutionBody>(http, "DeviceIdentityResolution")).Value;
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        var device = await RequireDeviceAsync(scope, deviceId, forUpdate: true, ct);
        var kind = device.IdentityState == "identity_conflict" ? device.ConflictKind : null;
        switch (body.Decision)
        {
            case "accept_new_fingerprint" when kind == "fingerprint":
                device.MachineFingerprintHash = device.ConflictFingerprintHash!;
                Devices.ClearConflict(device);
                AuditLog.Staff(scope, actor, "device.identity_resolved", "device", deviceId.ToString(), http.TraceIdentifier);
                break;
            case "accept_new_key" when kind == "key":
            {
                var (x, y) = AgentCrypto.ParseJwk(device.ConflictPublicKeyJwk!);
                AgentEnrollment.ReplaceKey(device, AgentCrypto.CanonicalJwk(x, y), AgentCrypto.Thumbprint(x, y), device.KeyProtection);
                Devices.ClearConflict(device);
                await Devices.DeleteSessionsAsync(scope, deviceId, ct);
                AuditLog.Staff(scope, actor, "device.key_replaced", "device", deviceId.ToString(), http.TraceIdentifier);
                AuditLog.Staff(scope, actor, "device.identity_resolved", "device", deviceId.ToString(), http.TraceIdentifier);
                break;
            }
            case "keep" when kind is not null:
                Devices.ClearConflict(device);
                AuditLog.Staff(scope, actor, "device.identity_resolved", "device", deviceId.ToString(), http.TraceIdentifier);
                break;
        }
        await scope.CommitAsync(ct);
        return Results.Json(DeviceDto.From(device, now), ApiJson.Options);
    }

    private static async Task<IResult> RequestScan(Guid organizationId, Guid deviceId, HttpContext http, RequestBodies bodies,
        DbScopes scopes, TimeProvider clock, CancellationToken ct)
    {
        const string operation = "requestDeviceScan";
        var actor = Actor.From(http.User);
        var request = await bodies.ReadAsync<ScanRequestCreateBody>(http, "ScanRequestCreate");
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var organization = await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        var device = await RequireDeviceAsync(scope, deviceId, forUpdate: true, ct);
        var replay = await Idempotency.FindReplayAsync(scope, operation, request.Value.IdempotencyKey, request.RawHash, now, ct);
        if (replay is not null)
        {
            var previous = await scope.Db.ScanRequests.AsNoTracking()
                .SingleAsync(r => r.OrganizationId == organizationId && r.Id == Guid.Parse(replay.ResultId!), ct);
            return Results.Json(ScanRequestDto.From(previous), ApiJson.Options, statusCode: StatusCodes.Status202Accepted);
        }
        OrganizationEndpoints.RequireActive(organization);
        if (device.Status != "active")
        {
            throw new ApiProblemException(ProblemCodes.ValidationFailed, "a revoked device cannot be asked for a scan");
        }
        var open = await scope.Db.ScanRequests.Where(r => r.OrganizationId == organizationId && r.DeviceId == deviceId
            && (r.State == "requested" || r.State == "delivered")).ToListAsync(ct);
        foreach (var stale in open.Where(r => r.ExpiresAt <= now))
        {
            stale.State = "expired";
        }
        await scope.Db.SaveChangesAsync(ct);
        var live = open.FirstOrDefault(r => r.ExpiresAt > now);
        if (live is null)
        {
            live = new ScanRequest
            {
                OrganizationId = organizationId, Id = Guid.CreateVersion7(), DeviceId = deviceId, RequestedBy = actor.EntraUserId,
                CreatedAt = now, ExpiresAt = now + ScanRequestLifetime, State = "requested",
            };
            scope.Db.ScanRequests.Add(live);
            await scope.Db.SaveChangesAsync(ct);
        }
        await Idempotency.RecordAsync(scope, operation, request.Value.IdempotencyKey, request.RawHash, 202, live.Id.ToString(), null, now, ct);
        AuditLog.Staff(scope, actor, "device.scan_request", "device", deviceId.ToString(), http.TraceIdentifier);
        await scope.CommitAsync(ct);
        return Results.Json(ScanRequestDto.From(live), ApiJson.Options, statusCode: StatusCodes.Status202Accepted);
    }
}
