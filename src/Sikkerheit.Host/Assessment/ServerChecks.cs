using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Agents;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.Organizations;

namespace Sikkerheit.Host.Assessment;

/// <summary>
/// The server checks of a device — SYS-001 (freshness of the full scan), SYS-002 (OS support) and SYS-003 (patch level) —
/// as observations with source=server and their assessments (05 «Выбор текущего состояния», step 7). They are written
/// with each batch that moves the projection, by patch_level_sweep as time passes and after a month of the catalog is
/// put into effect.
/// </summary>
public static class ServerChecks
{
    private const int InventoryBatches = 2000;

    /// <summary>
    /// The last collected WIN-011 of the device inside its freshness window among the batches that could change the
    /// projection (even when the newest batch has it unavailable); null when there is none.
    /// </summary>
    public static async Task<Observation?> InventoryAsync(DbScope scope, Guid deviceId, JsonElement configuration, DateTimeOffset now,
        CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var window = TimeSpan.FromHours(configuration.GetProperty("checks").GetProperty("WIN-011").GetProperty("freshnessWindowHours").GetInt32());
        var batches = (await Devices.ProjectionBatchesAsync(scope, deviceId, InventoryBatches, ct)).ToList();
        if (batches.Count == 0)
        {
            return null;
        }
        var rows = await scope.Db.Observations.AsNoTracking().Where(o => o.OrganizationId == org && o.CheckId == "WIN-011"
            && o.CollectionStatus == "collected" && o.ScanBatchId != null && batches.Contains(o.ScanBatchId.Value)
            && o.ObservedAt > now - window).ToListAsync(ct);
        return rows.OrderBy(o => batches.IndexOf(o.ScanBatchId!.Value)).FirstOrDefault();
    }

    public static async Task EvaluateAsync(DbScope scope, DeviceState device, Subject deviceSubject, PolicyRevision policy,
        ReleaseCatalogView catalog, DateTimeOffset now, string cause, bool onlyIfChanged, CancellationToken ct,
        bool freshnessOnly = false, bool deriveCause = false)
    {
        var org = scope.OrganizationId!.Value;
        using var configurationDocument = JsonDocument.Parse(policy.Configuration);
        var configuration = configurationDocument.RootElement;
        var checks = configuration.GetProperty("checks");
        var findings = await scope.Db.Findings.Where(f => f.OrganizationId == org && f.SubjectId == deviceSubject.Id
                                                         && f.CheckId.StartsWith("SYS-")).ToListAsync(ct);
        var previous = await LastAsync(scope, deviceSubject.Id, ct);
        var assessor = new Assessor(scope, policy, configuration, "current", cause, now, findings);

        // SYS-001: a full scan inside the window of freshness; always informational.
        var window = TimeSpan.FromHours(checks.GetProperty("SYS-001").GetProperty("freshnessWindowHours").GetInt32());
        var fresh = device.LastFullScanAt is { } scanned && now - scanned <= window;
        var freshness = new ServerOutcome(RuleOutcome.Pass(fresh ? "sys-001.fresh" : "sys-001.stale"), new JsonObject
        {
            ["lastFullScanAt"] = device.LastFullScanAt is null ? null : Platform.UtcTimeConverter.Format(device.LastFullScanAt.Value),
            ["lastSeenAt"] = device.LastSeenAt is null ? null : Platform.UtcTimeConverter.Format(device.LastSeenAt.Value),
        });
        Write(scope, assessor, deviceSubject, "SYS-001", freshness, null, now, checks, previous, onlyIfChanged, now, policy.Version, deriveCause);

        if (freshnessOnly)
        {
            await scope.Db.SaveChangesAsync(ct);
            return;
        }
        var inventory = await InventoryAsync(scope, device.Id, configuration, now, ct);
        if (inventory is null)
        {
            var missing = new ServerOutcome(RuleOutcome.Unknown("os_inventory_missing", "sys.os_inventory_missing"), null);
            Write(scope, assessor, deviceSubject, "SYS-002", missing, null, now, checks, previous, onlyIfChanged, now, policy.Version, deriveCause);
            Write(scope, assessor, deviceSubject, "SYS-003", missing, null, now, checks, previous, onlyIfChanged, now, policy.Version, deriveCause);
        }
        else
        {
            using var evidence = JsonDocument.Parse(inventory.Evidence!);
            Write(scope, assessor, deviceSubject, "SYS-002", ServerRules.OsSupport(evidence.RootElement, now), inventory, now, checks,
                previous, onlyIfChanged, inventory.ObservedAt, policy.Version, deriveCause);
            var parameters = checks.GetProperty("SYS-003").GetProperty("parameters");
            Write(scope, assessor, deviceSubject, "SYS-003", ServerRules.PatchLevel(evidence.RootElement, catalog, parameters, now),
                inventory, now, checks, previous, onlyIfChanged, inventory.ObservedAt, policy.Version, deriveCause);
        }
        await scope.Db.SaveChangesAsync(ct);
    }

    private sealed record Last(string? Result, string? Severity, string? ReasonCode, string Explanation, string Arguments, Guid? ObservationId,
        int PolicyVersion, string RuleVersion);

    private static async Task<Dictionary<string, Last>> LastAsync(DbScope scope, Guid subjectId, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var rows = await scope.Db.Assessments.AsNoTracking().Where(a => a.OrganizationId == org && a.SubjectId == subjectId
                && a.AssessmentScope == "current" && a.CheckId.StartsWith("SYS-"))
            .OrderByDescending(a => a.EvaluatedAt).ThenByDescending(a => a.Id).ToListAsync(ct);
        var map = new Dictionary<string, Last>();
        foreach (var a in rows)
        {
            using var snapshot = JsonDocument.Parse(a.BasisSnapshot);
            var args = snapshot.RootElement.TryGetProperty("arguments", out var value) ? value.GetRawText() : "null";
            map.TryAdd(a.CheckId, new Last(a.Result, a.Severity, a.ReasonCode,
                snapshot.RootElement.GetProperty("explanation").GetString() ?? "", args, a.ObservationId, a.EvaluatedPolicyVersion, a.RuleVersion));
        }
        return map;
    }

    private static void Write(DbScope scope, Assessor assessor, Subject subject, string checkId, ServerOutcome server,
        Observation? input, DateTimeOffset now, JsonElement checks, Dictionary<string, Last> previous, bool onlyIfChanged,
        DateTimeOffset observedAt, int policyVersion, bool deriveCause)
    {
        var mode = checks.GetProperty(checkId).GetProperty("assessmentMode").GetString()!;
        var outcome = server.Outcome;
        if (mode == "informational")
        {
            var transferable = outcome.ReasonCode is not null && Sikkerheit.Contracts.Catalog.InformationalReasons.Contains(outcome.ReasonCode);
            outcome = new RuleOutcome(null, null, transferable ? outcome.ReasonCode : null, outcome.Explanation, outcome.Arguments);
        }
        if (onlyIfChanged && previous.TryGetValue(checkId, out var last) && last.Result == outcome.Result && last.Severity == outcome.Severity
            && last.ReasonCode == outcome.ReasonCode && last.Explanation == outcome.Explanation && ArgumentsEqual(last, outcome)
            && (!deriveCause || (last.PolicyVersion == policyVersion && last.RuleVersion == RuleEngine.RuleVersion)))
        {
            return;
        }
        if (deriveCause)
        {
            // A recalculation: the change belongs to the new revision or the new rule only when that is what moved since the
            // last assessment of the pair; a change of the time or of the catalog is a change of the source (05).
            assessor.Cause = previous.TryGetValue(checkId, out var before) && before.PolicyVersion == policyVersion
                ? (before.RuleVersion != RuleEngine.RuleVersion ? "rule_change" : "source_change")
                : "policy_change";
        }
        Observation? row = null;
        if (server.Evidence is not null)
        {
            row = new Observation
            {
                OrganizationId = scope.OrganizationId!.Value, Id = Guid.CreateVersion7(), SubjectId = subject.Id, CheckId = checkId,
                Source = "server", InputObservationId = input?.Id, ObservedAt = now, ReceivedAt = now, CollectionStatus = "collected",
                Evidence = server.Evidence.ToJsonString(),
            };
            scope.Db.Observations.Add(row);
        }
        assessor.Add(subject, checkId, outcome, row, observedAt, now, policyVersion);
    }

    private static bool ArgumentsEqual(Last last, RuleOutcome outcome)
    {
        var current = outcome.Arguments is null ? "null"
            : new JsonObject(outcome.Arguments.Select(a => KeyValuePair.Create(a.Key, (JsonNode?)a.Value))).ToJsonString();
        return current == last.Arguments || JsonNode.DeepEquals(JsonNode.Parse(current), JsonNode.Parse(last.Arguments));
    }
}

/// <summary>
/// patch_level_sweep (03 «Правило SYS-003»; 05 «Выбор текущего состояния», step 7): SYS-001…SYS-003 of the devices of an
/// organization are evaluated again as the time passes and after a month of the release catalog is verified. The row of
/// each device is locked as for a batch; an assessment is written only when its outcome changed, with cause source_change.
/// </summary>
public sealed class PatchLevelSweepJob(DbScopes scopes, TimeProvider clock) : IJobHandler
{
    public string Type => "patch_level_sweep";

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        var org = lease.OrganizationId ?? throw new InvalidOperationException("patch_level_sweep needs an organization");
        List<Guid> devices;
        await using (var list = await scopes.OrganizationAsync(org, ct))
        {
            devices = (await Devices.ActiveAsync(list, org, ct)).Select(d => d.Id).ToList();
        }
        foreach (var id in devices)
        {
            await using var scope = await scopes.OrganizationAsync(org, ct);
            if (!await lease.HoldAsync(scope, ct))
            {
                throw new JobLeaseLostException();
            }
            var organization = await OrganizationLifecycle.FindAsync(scope, forUpdate: false, ct);
            if (organization is not { Status: "active" } || await Devices.LockAsync(scope, id, ct) is not { Status: "active" } device)
            {
                continue;
            }
            var policy = await Policies.CurrentAsync(scope, ct);
            var subject = await scope.Db.Subjects.SingleOrDefaultAsync(s => s.OrganizationId == org && s.Type == "device"
                && s.Key == id.ToString() && s.RetiredAt == null, ct);
            if (policy is null || subject is null)
            {
                continue;
            }
            var catalog = await ReleaseCatalogStore.ViewAsync(scope, ct);
            await ServerChecks.EvaluateAsync(scope, device, subject, policy, catalog, clock.GetUtcNow(), "source_change", onlyIfChanged: true, ct);
            await scope.CommitAsync(ct);
        }
        await using var done = await scopes.OrganizationAsync(org, ct);
        if (!await lease.HoldAsync(done, ct))
        {
            throw new JobLeaseLostException();
        }
        await lease.CompleteAsync(done, ct);
        await done.CommitAsync(ct);
    }
}
