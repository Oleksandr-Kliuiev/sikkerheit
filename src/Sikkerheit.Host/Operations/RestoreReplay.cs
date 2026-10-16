using System.Globalization;
using Sikkerheit.Host.Agents;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Exports;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.M365;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Reports;

namespace Sikkerheit.Host.Operations;

/// <param name="Since">The restore point T of the database (PITR).</param>
/// <param name="Drill">Drill from production: the Blob files may only be read, so they are listed, never moved or deleted.</param>
public sealed record RestoreOptions(DateTimeOffset Since, bool Drill);

public sealed record RestoreRecordResult(Guid Id, string Action, Guid OrganizationId, string TargetId, DateTimeOffset OccurredAt,
    string Outcome, string? Reason);

public sealed record RestorePostponedDeletion(Guid OrganizationId, DateTimeOffset? From, DateTimeOffset To);

public sealed record RestorePolicyEpoch(Guid OrganizationId, int MaxVersion, int NextVersion, bool AlreadyAdvanced);

public sealed record RestoreOrphanFile(string Container, string Key, string QuarantineKey, bool Moved);

public sealed record RestoreWeekMark(Guid OrganizationId, string Period, bool Marked);

public sealed record RestoreStep(string Name, DateTimeOffset StartedAt, DateTimeOffset FinishedAt);

public sealed record RestoreVerification(bool Passed, IReadOnlyList<string> Problems);

/// <summary>The report of one run (RB-05): what was read, applied, moved and checked, with the time of every step.</summary>
public sealed class RestoreReport
{
    public DateTimeOffset Since { get; init; }
    public DateTimeOffset ReplayFrom { get; init; }
    public bool Drill { get; init; }
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset FinishedAt { get; set; }
    public int RecordsRead { get; set; }
    public List<RestoreRecordResult> Records { get; } = [];
    public List<RestorePostponedDeletion> DeletionsPostponed { get; } = [];
    public List<RestorePolicyEpoch> PolicyEpochs { get; } = [];
    public List<RestoreOrphanFile> OrphanFiles { get; } = [];
    public List<string> DigestPeriodsMarked { get; } = [];
    public List<RestoreWeekMark> WeeklyReportsMarked { get; } = [];
    public List<Guid> OrganizationsWithoutEnrollmentKey { get; } = [];
    public int LeasesReset { get; set; }
    public RestoreVerification Verification { get; set; } = new(false, []);
    public List<RestoreStep> Steps { get; } = [];
}

/// <summary>
/// Steps 3–6 of 06 «Резервное копирование и восстановление» after a point-in-time restore of the database: the security
/// log is replayed from T − 5 minutes in time order, scheduled deletions are postponed, policy versions move to the next
/// epoch, files without rows go to quarantine, done periods are marked, leases are reset and the result is verified.
/// Every step is idempotent. Changes of other modules go through their interfaces; the run reads all organizations in
/// the read-all scope and changes each one in its own scope (02 «Разделение клиентов»).
/// </summary>
public sealed class RestoreReplay(DbScopes scopes, ISecurityLog securityLog, IFileStore files, TimeProvider clock,
    ILogger<RestoreReplay> logger)
{
    public const string AppliedAction = "restore.replay_applied";
    public static readonly TimeSpan ReplayMargin = TimeSpan.FromMinutes(5);

    private static readonly string[] AgentActions = ["device.revoke", "enrollment_key.revoke"];

    private static readonly string[] LifecycleActions =
        ["organization.disable", "organization.schedule_deletion", "organization.cancel_deletion", "organization.delete"];

    public async Task<RestoreReport> RunAsync(RestoreOptions options, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var run = new Run(options, now);
        var report = new RestoreReport
        {
            Since = options.Since, ReplayFrom = options.Since - ReplayMargin, Drill = options.Drill, StartedAt = now,
        };
        var records = new List<SecurityLogRecord>();
        await StepAsync(report, "replay_security_log", async () =>
        {
            await foreach (var record in securityLog.ReadSinceAsync(report.ReplayFrom, ct))
            {
                records.Add(record);
            }
            report.RecordsRead = records.Count;
            foreach (var record in records)
            {
                report.Records.Add(await ReplayAsync(run, record, ct));
            }
        });
        await StepAsync(report, "postpone_deletions", () => PostponeDeletionsAsync(run, report, ct));
        await StepAsync(report, "policy_epochs", () => AdvancePolicyEpochsAsync(run, report, ct));
        await StepAsync(report, "quarantine_files", () => QuarantineFilesAsync(run, report, ct));
        await StepAsync(report, "mark_done_periods", () => MarkDonePeriodsAsync(run, report, ct));
        await StepAsync(report, "enrollment_keys", async () =>
        {
            // An organization that had keys but none is active after the restore: the technician issues a new one (RB-05).
            foreach (var state in (await OrganizationsAsync(ct)).Where(o => o.Status == "active"))
            {
                await using var scope = await scopes.OrganizationAsync(state.Id, ct);
                if (!await AgentReplay.HasActiveKeyAsync(scope, ct))
                {
                    report.OrganizationsWithoutEnrollmentKey.Add(state.Id);
                }
            }
        });
        await StepAsync(report, "reset_leases", async () =>
        {
            await using var platform = await scopes.PlatformAsync(ct);
            report.LeasesReset = await JobQueue.ResetLeasesAsync(platform, now, ct);
            await platform.CommitAsync(ct);
        });
        await StepAsync(report, "verify", async () => report.Verification = await VerifyAsync(run, records, ct));
        report.FinishedAt = clock.GetUtcNow();
        logger.LogInformation("Restore replay from {ReplayFrom}: {Records} records, {Applied} applied, verification {Passed}",
            report.ReplayFrom, report.RecordsRead, report.Records.Count(r => r.Outcome == "applied"), report.Verification.Passed);
        return report;
    }

    /// <summary>The state of one run: «now» fixed at its start and the key that marks what this restore point did.</summary>
    private sealed record Run(RestoreOptions Options, DateTimeOffset Now)
    {
        public string Key { get; } = "restore:" + Options.Since.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);

        public string Correlation(string item) => Key + ":" + item;
    }

    private async Task StepAsync(RestoreReport report, string name, Func<Task> step)
    {
        var started = clock.GetUtcNow();
        await step();
        report.Steps.Add(new RestoreStep(name, started, clock.GetUtcNow()));
    }

    private async Task<RestoreRecordResult> ReplayAsync(Run run, SecurityLogRecord record, CancellationToken ct)
    {
        RestoreRecordResult Result(string outcome, string? reason = null) => new(record.Id, record.Action, record.OrganizationId,
            record.TargetId, record.OccurredAt, outcome, reason);

        if (record.Action != "m365.disconnect" && !LifecycleActions.Contains(record.Action) && !AgentActions.Contains(record.Action))
        {
            logger.LogWarning("Security log record {RecordId} has an unknown action {Action}", record.Id, record.Action);
            return Result("skipped", "unknown_action");
        }
        var correlation = run.Correlation($"{record.Action}:{record.Id:N}");
        await using var scope = await scopes.OrganizationAsync(record.OrganizationId, ct);
        var organization = await OrganizationLifecycle.LockAsync(scope, ct);
        if (record.Action == "organization.delete")
        {
            return Result(await ReplayDeletionAsync(run, scope, organization is not null, ct) ? "applied" : "already_satisfied",
                organization is null ? "organization_missing" : null);
        }
        if (organization is null)
        {
            return Result("skipped", "organization_missing");
        }
        if (await AuditLog.ExistsAsync(scope, AppliedAction, correlation, ct))
        {
            return Result("already_applied");
        }
        var applied = record.Action switch
        {
            "organization.disable" => OrganizationLifecycle.ReplayDisable(organization, record.OccurredAt),
            "organization.schedule_deletion" => OrganizationLifecycle.ReplayScheduleDeletion(organization, record.DeletionDueAt, run.Now),
            "organization.cancel_deletion" => OrganizationLifecycle.ReplayCancelDeletion(organization),
            "device.revoke" => await AgentReplay.RevokeDeviceAsync(scope, record, run.Now, ct),
            "enrollment_key.revoke" => await AgentReplay.RevokeKeyAsync(scope, record, ct),
            _ => await TenantConnections.DisconnectAsync(scope, run.Now, ct),
        };
        if (!applied)
        {
            return Result("already_satisfied");
        }
        AuditLog.System(scope, AppliedAction, record.TargetType, record.TargetId, correlation);
        await scope.CommitAsync(ct);
        logger.LogWarning("Restore replay applied {Action} to organization {OrganizationId}", record.Action, record.OrganizationId);
        return Result("applied");
    }

    /// <summary>
    /// A deletion that happened is repeated at once (F11): rows, files and the tombstone. An organization missing from the
    /// restored database but without a tombstone was created after T; its files are removed and the tombstone written.
    /// </summary>
    private async Task<bool> ReplayDeletionAsync(Run run, DbScope scope, bool exists, CancellationToken ct)
    {
        if (!exists)
        {
            await using var platform = await scopes.PlatformAsync(ct);
            if (await OrganizationDeletion.TombstoneExistsAsync(platform, scope.OrganizationId!.Value, ct))
            {
                return false;
            }
        }
        await OrganizationDeletion.DeleteAsync(scope, files, run.Now, null, deleteFiles: !run.Options.Drill, ct);
        await scope.CommitAsync(ct);
        logger.LogWarning("Restore replay deleted organization {OrganizationId}", scope.OrganizationId);
        return true;
    }

    private async Task<IReadOnlyList<OrganizationState>> OrganizationsAsync(CancellationToken ct)
    {
        await using var all = await scopes.ReadAllAsync(ct);
        return await OrganizationLifecycle.ListAsync(all, ct);
    }

    /// <summary>Step 4: no organization is deleted earlier than 7 days after the restore; Admin checks the list.</summary>
    private async Task PostponeDeletionsAsync(Run run, RestoreReport report, CancellationToken ct)
    {
        foreach (var state in (await OrganizationsAsync(ct)).Where(o => o.Status == "deletion_scheduled"))
        {
            await using var scope = await scopes.OrganizationAsync(state.Id, ct);
            var organization = await OrganizationLifecycle.LockAsync(scope, ct);
            if (organization is null)
            {
                continue;
            }
            var previous = OrganizationLifecycle.PostponeDeletion(organization, run.Now);
            if (previous is not null)
            {
                AuditLog.System(scope, "restore.deletion_postponed", "organization", state.Id.ToString(),
                    run.Correlation("deletion_postponed"));
                await scope.CommitAsync(ct);
            }
            report.DeletionsPostponed.Add(new RestorePostponedDeletion(state.Id, previous ?? organization.DeletionDueAt,
                organization.DeletionDueAt!.Value));
        }
    }

    /// <summary>Step 5: the next policy version of every organization moves to the next epoch, once per restore point.</summary>
    private async Task AdvancePolicyEpochsAsync(Run run, RestoreReport report, CancellationToken ct)
    {
        var correlation = run.Correlation("policy_epoch");
        foreach (var state in await OrganizationsAsync(ct))
        {
            await using var scope = await scopes.OrganizationAsync(state.Id, ct);
            var organization = await OrganizationLifecycle.LockAsync(scope, ct);
            if (organization is null)
            {
                continue;
            }
            var max = await OrganizationLifecycle.MaxPolicyVersionAsync(scope, ct);
            if (await AuditLog.ExistsAsync(scope, "restore.policy_epoch", correlation, ct))
            {
                report.PolicyEpochs.Add(new RestorePolicyEpoch(state.Id, max, organization.NextPolicyVersion, AlreadyAdvanced: true));
                continue;
            }
            var next = OrganizationLifecycle.AdvancePolicyEpoch(organization, max);
            AuditLog.System(scope, "restore.policy_epoch", "organization", state.Id.ToString(), correlation);
            await scope.CommitAsync(ct);
            report.PolicyEpochs.Add(new RestorePolicyEpoch(state.Id, max, next, AlreadyAdvanced: false));
        }
    }

    /// <summary>
    /// Step 5: report and export files without a row in the restored database move to restore-orphans/, where a lifecycle
    /// rule deletes them after 30 days; a drill only lists them.
    /// </summary>
    private async Task QuarantineFilesAsync(Run run, RestoreReport report, CancellationToken ct)
    {
        IReadOnlySet<string> reports, exports;
        await using (var all = await scopes.ReadAllAsync(ct))
        {
            reports = await ReportService.KnownFileKeysAsync(all, ct);
            exports = await OrganizationExports.KnownFileKeysAsync(all, ct);
        }
        foreach (var (container, known) in new[] { (FileContainers.Reports, reports), (FileContainers.Exports, exports) })
        {
            var orphans = new List<string>();
            await foreach (var key in files.ListAsync(container, "", ct))
            {
                if (!key.StartsWith(FileContainers.QuarantinePrefix, StringComparison.Ordinal) && !known.Contains(key))
                {
                    orphans.Add(key);
                }
            }
            foreach (var key in orphans)
            {
                var target = FileContainers.QuarantinePrefix + key;
                if (!run.Options.Drill)
                {
                    await files.MoveAsync(container, key, target, ct);
                    logger.LogWarning("Restore moved {Container}/{Key} without a database row to quarantine", container, key);
                }
                report.OrphanFiles.Add(new RestoreOrphanFile(container, key, target, Moved: !run.Options.Drill));
            }
        }
    }

    /// <summary>
    /// Step 5: digests of the days after T were sent already, and a week whose report file was found in quarantine already
    /// reached the client; neither is repeated. Collection and retention run in their usual order.
    /// </summary>
    private async Task MarkDonePeriodsAsync(Run run, RestoreReport report, CancellationToken ct)
    {
        var existing = (await OrganizationsAsync(ct)).Select(o => o.Id).ToHashSet();
        await using var platform = await scopes.PlatformAsync(ct);
        foreach (var period in TeamsDigestJob.PeriodsBetween(run.Options.Since, run.Now))
        {
            await TeamsDigestJob.MarkSentAsync(platform, period, run.Now, ct);
            report.DigestPeriodsMarked.Add(period);
        }
        foreach (var file in report.OrphanFiles.Where(f => f.Container == FileContainers.Reports))
        {
            if (ReportService.TryParseFileKey(file.Key, out var organizationId, out var period) && existing.Contains(organizationId)
                && report.WeeklyReportsMarked.All(m => m.OrganizationId != organizationId || m.Period != period))
            {
                var marked = await JobQueue.MarkDoneAsync(platform, "weekly_report", organizationId, period, run.Now, ct);
                report.WeeklyReportsMarked.Add(new RestoreWeekMark(organizationId, period, marked));
            }
        }
        await platform.CommitAsync(ct);
    }

    /// <summary>
    /// Step 6: every object of the journal is at least as restrictive as its last record, no deletion comes sooner than
    /// 7 days and no job holds a lease. The Graph key and enrollment keys are checked by RB-05 outside the command.
    /// </summary>
    private async Task<RestoreVerification> VerifyAsync(Run run, IReadOnlyList<SecurityLogRecord> records, CancellationToken ct)
    {
        var problems = new List<string>();
        var organizations = (await OrganizationsAsync(ct)).ToDictionary(o => o.Id);
        foreach (var last in records.Where(r => LifecycleActions.Contains(r.Action)).GroupBy(r => r.OrganizationId)
                     .Select(g => g.OrderBy(r => r.OccurredAt).ThenBy(r => r.Id).Last()))
        {
            organizations.TryGetValue(last.OrganizationId, out var state);
            var satisfied = last.Action switch
            {
                "organization.disable" => state is null || state.Status != "active",
                "organization.schedule_deletion" => state is null || state.Status == "deletion_scheduled",
                "organization.cancel_deletion" => state is null || state.Status != "deletion_scheduled",
                _ => state is null,
            };
            if (!satisfied)
            {
                problems.Add($"organization {last.OrganizationId} is {state?.Status ?? "missing"} after {last.Action} {last.Id}");
            }
        }
        foreach (var organizationId in records.Where(r => r.Action == "m365.disconnect").Select(r => r.OrganizationId).Distinct()
                     .Where(organizations.ContainsKey))
        {
            await using var scope = await scopes.OrganizationAsync(organizationId, ct);
            if (await TenantConnections.IsOpenAsync(scope, ct))
            {
                problems.Add($"organization {organizationId} still has an open Microsoft 365 connection after m365.disconnect");
            }
        }
        foreach (var record in records.Where(r => r.Action is "device.revoke" or "enrollment_key.revoke" && organizations.ContainsKey(r.OrganizationId)))
        {
            await using var scope = await scopes.OrganizationAsync(record.OrganizationId, ct);
            var satisfied = record.Action == "device.revoke"
                ? await AgentReplay.InstallationRevokedAsync(scope, record, ct)
                : await AgentReplay.KeyRevokedAsync(scope, record, ct);
            if (!satisfied)
            {
                problems.Add($"{record.Action} {record.Id} of organization {record.OrganizationId} is not in effect after the restore");
            }
        }
        foreach (var state in organizations.Values.Where(o => o.Status == "deletion_scheduled"
                                                              && o.DeletionDueAt < run.Now + OrganizationLifecycle.RestoreDeletionGrace))
        {
            problems.Add($"organization {state.Id} is due for deletion at {state.DeletionDueAt:O}, earlier than 7 days after the restore");
        }
        await using (var platform = await scopes.PlatformAsync(ct))
        {
            if (await JobQueue.LeasedCountAsync(platform, ct) is var leased and > 0)
            {
                problems.Add($"{leased} jobs still hold a lease");
            }
        }
        foreach (var problem in problems)
        {
            logger.LogError("Restore verification failed: {Problem}", problem);
        }
        return new RestoreVerification(problems.Count == 0, problems);
    }
}
