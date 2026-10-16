using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Agents;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Organizations;

namespace Sikkerheit.Host.Assessment;

/// <summary>An observation of a batch as the agent API passes it on; the subject is a device or a volume of the device.</summary>
public sealed record ScanObservation(
    string CheckId, string SubjectType, string? VolumeId, string? MountPoint, DateTimeOffset ObservedAt, string CollectionStatus,
    JsonElement? Evidence, string? ReasonCode);

/// <summary>The accepted batch: times, the clock flag and whether it replaces the current projection of the device.</summary>
public sealed record IntakeBatch(
    Guid BatchId, DateTimeOffset CompletedAt, DateTimeOffset ReceivedAt, int PolicyVersion, bool ClockInconsistent,
    bool ReplacesProjection, bool Full, DateTimeOffset LastSeenAt, DateTimeOffset? LastFullScanAt);

/// <summary>The reboot episode of WIN-007 (05 «Субъекты…», 03 «Правило WIN-007»): the start and the boot session it belongs to.</summary>
public sealed record DeviceEpisode(DateTimeOffset? Since, DateTimeOffset? BootAt);

/// <summary>
/// Evaluation of a batch of a Windows agent (05 «Порядок приёма пакета», «Выбор текущего состояния»): subjects,
/// observations, assessments, findings and events in the transaction of the intake. A batch that replaces the projection
/// is assessed by the current policy (scope current) and moves the findings; any other batch, and every batch with the
/// clock flag, is history by the policy of its source (scope historical) and writes no events.
/// </summary>
public static class WindowsEvaluator
{
    private static readonly string[] AgentChecks = Catalog.Checks.Where(c => c.Source == "agent").Select(c => c.CheckId).ToArray();
    private static readonly TimeSpan SameBootSession = TimeSpan.FromMinutes(2);

    /// <summary>The identifiers of the contract: the subject of a Windows observation is the device or its volume.</summary>
    public static string VolumeKey(Guid deviceId, string volumeId) => deviceId.ToString() + "/" + volumeId;

    public static async Task<DeviceEpisode> IngestAsync(DbScope scope, DeviceState device, IntakeBatch batch,
        IReadOnlyList<ScanObservation> items, PolicyRevision current, PolicyRevision source, ReleaseCatalogView catalog,
        CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var policy = batch.ReplacesProjection && !batch.ClockInconsistent ? current : source;
        using var configurationDocument = JsonDocument.Parse(policy.Configuration);
        var configuration = configurationDocument.RootElement;
        var active = configuration.GetProperty("activeCheckIds").EnumerateArray().Select(e => e.GetString()!).ToHashSet();
        var subjects = await scope.Db.Subjects.Where(s => s.OrganizationId == org && s.DeviceId == device.Id).ToListAsync(ct);
        var now = batch.ReceivedAt;

        Subject SubjectFor(string type, string key, string? name)
        {
            var subject = subjects.FirstOrDefault(s => s.Type == type && s.Key == key);
            if (subject is null)
            {
                subject = new Subject
                {
                    OrganizationId = org, Id = Guid.CreateVersion7(), Type = type, Key = key, DisplayName = name ?? device.DisplayName,
                    DeviceId = device.Id, FirstSeenAt = now, LastSeenAt = now,
                };
                scope.Db.Subjects.Add(subject);
                subjects.Add(subject);
            }
            if (batch.ReplacesProjection)
            {
                subject.LastSeenAt = now;
                subject.RetiredAt = null;
                subject.DisplayName = name ?? subject.DisplayName;
            }
            return subject;
        }

        var deviceSubject = SubjectFor("device", device.Id.ToString(), device.DisplayName);
        var observations = new List<(ScanObservation Item, Subject Subject, Observation Row)>();
        foreach (var item in items)
        {
            var subject = item.SubjectType == "volume"
                ? SubjectFor("volume", VolumeKey(device.Id, item.VolumeId!), DeviceSubjects.VolumeName(device.DisplayName, item.MountPoint ?? item.VolumeId!))
                : deviceSubject;
            var collected = item.CollectionStatus == "collected";
            var row = new Observation
            {
                OrganizationId = org, Id = Guid.CreateVersion7(), SubjectId = subject.Id, CheckId = item.CheckId, Source = "agent",
                ScanBatchId = batch.BatchId, ObservedAt = item.ObservedAt, ReceivedAt = now, CollectionStatus = item.CollectionStatus,
                Evidence = collected ? item.Evidence!.Value.GetRawText() : null, ReasonCode = collected ? null : item.ReasonCode,
            };
            scope.Db.Observations.Add(row);
            observations.Add((item, subject, row));
        }

        var episode = new DeviceEpisode(device.RebootEpisodeSince, device.RebootEpisodeBootAt);
        if (batch.ReplacesProjection && !batch.ClockInconsistent
            && observations.FirstOrDefault(o => o.Item.CheckId == "WIN-007" && o.Item.CollectionStatus == "collected") is { Item: not null } reboot)
        {
            episode = NextEpisode(episode, reboot.Item.Evidence!.Value, reboot.Item.ObservedAt);
        }

        var findings = await scope.Db.Findings.Where(f => f.OrganizationId == org
            && scope.Db.Subjects.Any(s => s.OrganizationId == org && s.Id == f.SubjectId && s.DeviceId == device.Id)).ToListAsync(ct);
        var assessor = new Assessor(scope, policy, configuration, batch.ReplacesProjection && !batch.ClockInconsistent ? "current" : "historical",
            "source_change", now, findings);

        var inputs = observations.Where(o => o.Item.SubjectType == "device")
            .ToDictionary(o => o.Item.CheckId, o => ToInput(o.Row, o.Subject));
        var context = new WindowsContext(batch.ClockInconsistent, inputs, episode.Since);
        foreach (var (item, subject, row) in observations)
        {
            // An observation of a check that the policy of the batch does not make active is not assessed.
            if (!active.Contains(item.CheckId))
            {
                continue;
            }
            var outcome = WindowsRules.Evaluate(ToInput(row, subject), item.CheckId, configuration, context);
            assessor.Add(subject, item.CheckId, outcome, row, row.ObservedAt, now, batch.PolicyVersion);
        }

        // Volumes: a full batch with an OS volume of another volumeId retires the old one (positive evidence only).
        var batchVolumes = observations.Where(o => o.Item.SubjectType == "volume").Select(o => o.Subject.Id).ToHashSet();
        if (batch.Full && batch.ReplacesProjection && !batch.ClockInconsistent && batchVolumes.Count > 0)
        {
            var machine = new FindingMachine(scope.Db, org, now);
            foreach (var old in subjects.Where(s => s.Type == "volume" && s.RetiredAt is null && !batchVolumes.Contains(s.Id)).ToList())
            {
                old.RetiredAt = now;
                foreach (var finding in findings.Where(f => f.SubjectId == old.Id))
                {
                    machine.Retire(finding, "source_change");
                }
            }
        }

        // Active checks without an observation of the expected subject: unknown/missing_observation.
        var present = observations.Select(o => (o.Subject.Id, o.Item.CheckId)).ToHashSet();
        foreach (var checkId in AgentChecks.Where(active.Contains))
        {
            var definition = Catalog.Check(checkId);
            var expected = definition.SubjectType == "device"
                ? [deviceSubject]
                : subjects.Where(s => s.Type == "volume" && s.RetiredAt is null).ToList();
            // missing_observation is written only for assessed checks (05 «Выбор текущего состояния», п. 3).
            if (configuration.GetProperty("checks").GetProperty(checkId).GetProperty("assessmentMode").GetString() != "assessed")
            {
                continue;
            }
            foreach (var subject in expected.Where(s => !present.Contains((s.Id, checkId))))
            {
                var outcome = WindowsRules.Evaluate(null, checkId, configuration, context);
                assessor.Add(subject, checkId, outcome, null, batch.CompletedAt, now, batch.PolicyVersion);
            }
        }
        await scope.Db.SaveChangesAsync(ct);

        if (batch.ReplacesProjection && !batch.ClockInconsistent)
        {
            await ServerChecks.EvaluateAsync(scope, device with { LastSeenAt = batch.LastSeenAt, LastFullScanAt = batch.LastFullScanAt },
                deviceSubject, current, catalog, now, "source_change", onlyIfChanged: false, ct);
        }
        return episode;
    }

    /// <summary>The episode after a collected WIN-007 (03 «Правило WIN-007»).</summary>
    public static DeviceEpisode NextEpisode(DeviceEpisode episode, JsonElement evidence, DateTimeOffset observedAt)
    {
        if (!evidence.GetProperty("rebootRequired").GetBoolean())
        {
            return new DeviceEpisode(null, null);
        }
        var boot = DateTimeOffset.Parse(evidence.GetProperty("lastBootAt").GetString()!, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal);
        return episode is { Since: not null, BootAt: { } started } && (boot - started).Duration() <= SameBootSession
            ? episode
            : new DeviceEpisode(observedAt, boot);
    }

    public static RuleInput ToInput(Observation row, Subject subject) => new(row.CheckId, subject.Key, row.CollectionStatus,
        row.Evidence is null ? null : JsonDocument.Parse(row.Evidence).RootElement, row.ReasonCode, row.ObservedAt);

    /// <summary>
    /// recalculate_policy for the devices of an organization (05 «Выбор текущего состояния», step 4): the observations of the
    /// projection batch are assessed again by the newest revision and the current rules. The cause is rule_change when only
    /// the ruleVersion moved since the last assessment of the pair, otherwise policy_change.
    /// </summary>
    public static async Task RecalculateAsync(DbScope scope, DeviceState device, PolicyRevision policy, ReleaseCatalogView catalog,
        DateTimeOffset now, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        using var configurationDocument = JsonDocument.Parse(policy.Configuration);
        var configuration = configurationDocument.RootElement;
        var active = configuration.GetProperty("activeCheckIds").EnumerateArray().Select(e => e.GetString()!).ToHashSet();
        var subjects = await scope.Db.Subjects.Where(s => s.OrganizationId == org && s.DeviceId == device.Id && s.RetiredAt == null)
            .ToListAsync(ct);
        var deviceSubject = subjects.FirstOrDefault(s => s.Type == "device");
        if (deviceSubject is null)
        {
            return;
        }
        var findings = await scope.Db.Findings.Where(f => f.OrganizationId == org && subjects.Select(s => s.Id).Contains(f.SubjectId))
            .ToListAsync(ct);
        var machine = new FindingMachine(scope.Db, org, now);
        var batchId = await Devices.ProjectionBatchAsync(scope, device.Id, ct);
        var rows = batchId is null ? [] : await scope.Db.Observations.AsNoTracking()
            .Where(o => o.OrganizationId == org && o.ScanBatchId == batchId).ToListAsync(ct);
        var batchSourceVersion = batchId is null ? policy.Version : await Devices.BatchPolicyVersionAsync(scope, batchId.Value, ct);
        var previous = await LastAssessmentsAsync(scope, subjects.Select(s => s.Id).ToList(), ct);
        var bySubject = subjects.ToDictionary(s => s.Id);
        var inputs = rows.Where(r => bySubject.TryGetValue(r.SubjectId, out var s) && s.Type == "device")
            .ToDictionary(r => r.CheckId, r => ToInput(r, bySubject[r.SubjectId]));
        var context = new WindowsContext(false, inputs, device.RebootEpisodeSince);
        var assessor = new Assessor(scope, policy, configuration, "current", "policy_change", now, findings);
        var seen = new HashSet<(Guid, string)>();
        foreach (var row in rows)
        {
            if (!bySubject.TryGetValue(row.SubjectId, out var subject) || !active.Contains(row.CheckId))
            {
                continue;
            }
            seen.Add((subject.Id, row.CheckId));
            if (AlreadyEvaluated(previous, subject.Id, row.CheckId, policy.Version, row.Id))
            {
                continue;
            }
            var outcome = WindowsRules.Evaluate(ToInput(row, subject), row.CheckId, configuration, context);
            assessor.Cause = CauseOf(previous, subject.Id, row.CheckId, policy.Version);
            assessor.Add(subject, row.CheckId, outcome, row, row.ObservedAt, now, batchSourceVersion);
        }
        foreach (var checkId in AgentChecks)
        {
            var definition = Catalog.Check(checkId);
            var expected = definition.SubjectType == "device" ? [deviceSubject] : subjects.Where(s => s.Type == "volume").ToList();
            foreach (var subject in expected.Where(s => !seen.Contains((s.Id, checkId))))
            {
                var existing = findings.FirstOrDefault(f => f.SubjectId == subject.Id && f.CheckId == checkId);
                if (!active.Contains(checkId))
                {
                    if (existing is not null)
                    {
                        machine.PolicyRemoved(existing);
                    }
                    continue;
                }
                var mode = configuration.GetProperty("checks").GetProperty(checkId).GetProperty("assessmentMode").GetString();
                if (batchId is null || mode != "assessed" || AlreadyEvaluated(previous, subject.Id, checkId, policy.Version, null))
                {
                    continue;
                }
                assessor.Cause = CauseOf(previous, subject.Id, checkId, policy.Version);
                assessor.Add(subject, checkId, WindowsRules.Evaluate(null, checkId, configuration, context), null, now, now, batchSourceVersion);
            }
        }
        await scope.Db.SaveChangesAsync(ct);
        if (batchId is not null)
        {
            await ServerChecks.EvaluateAsync(scope, device, deviceSubject, policy, catalog, now, "source_change", onlyIfChanged: true, ct,
                deriveCause: true);
        }
    }

    private sealed record LastAssessment(int PolicyVersion, string RuleVersion, Guid? ObservationId);

    private static async Task<Dictionary<(Guid, string), LastAssessment>> LastAssessmentsAsync(DbScope scope, IReadOnlyList<Guid> subjects,
        CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var rows = await scope.Db.Assessments.AsNoTracking()
            .Where(a => a.OrganizationId == org && subjects.Contains(a.SubjectId) && a.AssessmentScope == "current"
                        && a.CheckId.StartsWith("WIN-"))
            .OrderByDescending(a => a.EvaluatedAt).ThenByDescending(a => a.Id).ToListAsync(ct);
        var map = new Dictionary<(Guid, string), LastAssessment>();
        foreach (var a in rows)
        {
            map.TryAdd((a.SubjectId, a.CheckId), new LastAssessment(a.EvaluatedPolicyVersion, a.RuleVersion, a.ObservationId));
        }
        return map;
    }

    private static bool AlreadyEvaluated(Dictionary<(Guid, string), LastAssessment> previous, Guid subject, string checkId, int policyVersion,
        Guid? observation) =>
        previous.TryGetValue((subject, checkId), out var last) && last.PolicyVersion == policyVersion
        && last.RuleVersion == RuleEngine.RuleVersion && last.ObservationId == observation;

    private static string CauseOf(Dictionary<(Guid, string), LastAssessment> previous, Guid subject, string checkId, int policyVersion) =>
        previous.TryGetValue((subject, checkId), out var last) && last.PolicyVersion == policyVersion && last.RuleVersion != RuleEngine.RuleVersion
            ? "rule_change"
            : "policy_change";
}

/// <summary>Writes the assessments of one evaluation and moves the findings (current scope) through the state machine.</summary>
internal sealed class Assessor(DbScope scope, PolicyRevision policy, JsonElement configuration, string assessmentScope, string cause,
    DateTimeOffset now, List<Finding> findings)
{
    private readonly FindingMachine _machine = new(scope.Db, scope.OrganizationId!.Value, now);

    public string Cause { get; set; } = cause;

    public Data.Assessment Add(Subject subject, string checkId, RuleOutcome outcome, Observation? observation, DateTimeOffset observedAt,
        DateTimeOffset receivedAt, int sourcePolicyVersion)
    {
        var mode = configuration.GetProperty("checks").GetProperty(checkId).GetProperty("assessmentMode").GetString()!;
        var assessment = new Data.Assessment
        {
            OrganizationId = scope.OrganizationId!.Value, Id = Guid.CreateVersion7(), ObservationId = observation?.Id,
            SubjectId = subject.Id, CheckId = checkId, RuleId = checkId, RuleVersion = RuleEngine.RuleVersion,
            SourcePolicyVersion = sourcePolicyVersion, EvaluatedPolicyVersion = policy.Version, AssessmentScope = assessmentScope,
            AssessmentMode = mode, Result = outcome.Result, Severity = outcome.Result == "fail" ? outcome.Severity : null,
            ReasonCode = outcome.ReasonCode, ObservedAt = observedAt, ReceivedAt = receivedAt, EvaluatedAt = now,
            BasisSnapshot = M365Evaluator.Snapshot(checkId, mode, policy.Version, outcome, observedAt),
        };
        scope.Db.Assessments.Add(assessment);
        if (assessmentScope == "current")
        {
            var finding = findings.FirstOrDefault(f => f.SubjectId == subject.Id && f.CheckId == checkId);
            // Edition and Defender state are facts of the source; the other not_applicable cases follow the policy.
            var bySource = Cause == "source_change" && outcome.Result == "not_applicable"
                           && outcome.Explanation is "win.not_applicable.edition" or "win-004.not_applicable.defender";
            _machine.Apply(finding, assessment, Cause, bySource);
            if (finding is null && scope.Db.ChangeTracker.Entries<Finding>().FirstOrDefault(e =>
                    e.State == EntityState.Added && e.Entity.SubjectId == subject.Id && e.Entity.CheckId == checkId) is { } added)
            {
                findings.Add(added.Entity);
            }
        }
        return assessment;
    }
}
