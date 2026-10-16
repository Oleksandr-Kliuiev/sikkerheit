using System.Globalization;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Agents;

public sealed record EnrollmentKeyCreateBody(string Label);

public sealed record EnrollmentKeySummaryDto(
    Guid Id, string Label, string KeyPrefix, DateTimeOffset CreatedAt, Guid CreatedBy, DateTimeOffset? RevokedAt,
    DateTimeOffset? LastUsedAt, int EnrolledDevices);

/// <summary>Enrollment keys of the organization (04 «Ключ регистрации организации», FR-09): create, list, revoke.</summary>
public static class EnrollmentKeys
{
    public const int MaxActive = 2;

    public static void Map(IEndpointRouteBuilder org)
    {
        org.MapPost("/enrollment-keys", Create).RequireStaff(StaffRoles.AdminOnly);
        org.MapGet("/enrollment-keys", List).RequireStaff(StaffRoles.AdminOnly);
        org.MapPost("/enrollment-keys/{keyId:guid}/revoke", Revoke).RequireStaff(StaffRoles.AdminOnly);
    }

    /// <summary>The organization and the id of the key with this hash; the lookup by secret precedes the scope (02).</summary>
    public static async Task<(Guid OrganizationId, Guid KeyId)?> OwnerAsync(DbScopes scopes, string hash, CancellationToken ct)
    {
        await using var platform = await scopes.PlatformAsync(ct);
        await using var command = new Npgsql.NpgsqlCommand("select organization_id, key_id from app.enrollment_key_owner(@hash)",
            platform.Connection, platform.Transaction);
        command.Parameters.AddWithValue("hash", hash);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? (reader.GetGuid(0), reader.GetGuid(1)) : null;
    }

    public static async Task<EnrollmentKey?> FindAsync(DbScope scope, Guid keyId, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        return await scope.Db.EnrollmentKeys.SingleOrDefaultAsync(k => k.OrganizationId == org && k.Id == keyId, ct);
    }

    private static async Task<IResult> Create(Guid organizationId, HttpContext http, RequestBodies bodies, DbScopes scopes,
        TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var body = (await bodies.ReadAsync<EnrollmentKeyCreateBody>(http, "EnrollmentKeyCreate")).Value;
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        // The organization row serializes the creation: two concurrent requests cannot make a third active key.
        var organization = await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: true, ct);
        OrganizationEndpoints.RequireActive(organization);
        var active = await scope.Db.EnrollmentKeys.CountAsync(k => k.OrganizationId == organizationId && k.RevokedAt == null, ct);
        if (active >= MaxActive)
        {
            throw new ApiProblemException(ProblemCodes.ValidationFailed, "an organization has at most two active enrollment keys");
        }
        var secret = "sikk_" + AgentCrypto.Base64Url(RandomNumberGenerator.GetBytes(32));
        var key = new EnrollmentKey
        {
            OrganizationId = organizationId, Id = Guid.CreateVersion7(), KeyHash = AgentCrypto.Sha256Hex(secret),
            KeyPrefix = secret[..9], Label = body.Label, CreatedAt = now, CreatedBy = actor.EntraUserId,
        };
        scope.Db.EnrollmentKeys.Add(key);
        AuditLog.Staff(scope, actor, "enrollment_key.create", "enrollment_key", key.Id.ToString(), http.TraceIdentifier);
        await scope.CommitAsync(ct);
        return Results.Json(new { id = key.Id, enrollmentKey = secret, label = key.Label, createdAt = key.CreatedAt },
            ApiJson.Options, statusCode: StatusCodes.Status201Created);
    }

    private static async Task<IResult> List(Guid organizationId, DbScopes scopes, Cursors cursors, string? cursor, string? limit,
        CancellationToken ct)
    {
        var size = OrganizationEndpoints.Limit(limit);
        var position = cursors.Read(cursor, "listEnrollmentKeys", organizationId, "");
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        var query = scope.Db.EnrollmentKeys.AsNoTracking().Where(k => k.OrganizationId == organizationId);
        if (position is not null)
        {
            var before = DateTimeOffset.Parse(position[0], CultureInfo.InvariantCulture);
            var beforeId = Guid.Parse(position[1]);
            query = query.Where(k => k.CreatedAt < before || (k.CreatedAt == before && k.Id.CompareTo(beforeId) < 0));
        }
        var rows = await query.OrderByDescending(k => k.CreatedAt).ThenByDescending(k => k.Id).Take(size + 1).ToListAsync(ct);
        string? next = null;
        if (rows.Count > size)
        {
            rows.RemoveAt(size);
            next = cursors.Create("listEnrollmentKeys", organizationId, "",
                [rows[^1].CreatedAt.ToString("O", CultureInfo.InvariantCulture), rows[^1].Id.ToString()]);
        }
        var ids = rows.Select(r => r.Id).ToList();
        var counts = await scope.Db.Devices.AsNoTracking()
            .Where(d => d.OrganizationId == organizationId && d.EnrollmentKeyId != null && ids.Contains(d.EnrollmentKeyId.Value))
            .GroupBy(d => d.EnrollmentKeyId!.Value).Select(g => new { Id = g.Key, Count = g.Count() }).ToListAsync(ct);
        var enrolled = counts.ToDictionary(c => c.Id, c => c.Count);
        var items = rows.Select(k => new EnrollmentKeySummaryDto(k.Id, k.Label, k.KeyPrefix, k.CreatedAt, k.CreatedBy, k.RevokedAt,
            k.LastUsedAt, enrolled.GetValueOrDefault(k.Id))).ToList();
        return Results.Json(new Page<EnrollmentKeySummaryDto>(items, next), ApiJson.Options);
    }

    private static async Task<IResult> Revoke(Guid organizationId, Guid keyId, HttpContext http, DbScopes scopes,
        ISecurityLog securityLog, TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        var key = await scope.Db.EnrollmentKeys.FromSqlInterpolated(
                $"select * from enrollment_key where organization_id = {organizationId} and id = {keyId} for update")
            .SingleOrDefaultAsync(ct) ?? throw new ApiProblemException(ProblemCodes.NotFound);
        if (key.RevokedAt is null)
        {
            // The record comes first (04 «Журнал безопасности»): without it the key stays active and the call answers 503.
            await SecurityRecords.AppendAsync(http, securityLog, new SecurityLogRecord(Guid.CreateVersion7(), "enrollment_key.revoke",
                organizationId, "enrollment_key", keyId.ToString(), now, http.TraceIdentifier, actor.EntraUserId,
                EnrollmentKeyId: keyId), ct);
            key.RevokedAt = now;
            AuditLog.Staff(scope, actor, "enrollment_key.revoke", "enrollment_key", keyId.ToString(), http.TraceIdentifier);
        }
        await scope.CommitAsync(ct);
        return Results.NoContent();
    }
}

/// <summary>The security log write of a restrictive action with the 5-second limit and 503 on failure (04).</summary>
public static class SecurityRecords
{
    public static async Task AppendAsync(HttpContext http, ISecurityLog securityLog, SecurityLogRecord record, CancellationToken ct)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await securityLog.AppendAsync(record, timeout.Token);
        }
        catch (Exception error) when (error is SecurityLogUnavailableException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Sikkerheit.SecurityLog")
                .LogError(error, "Security log record {Action} was not created; the action is refused with 503", record.Action);
            throw new ApiProblemException(ProblemCodes.TemporarilyUnavailable, "security log is unavailable");
        }
    }
}
