using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using NpgsqlTypes;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.M365;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Assessment;

/// <summary>
/// Writes a collection run in its final transaction (05 «Подключение M365 и сбор»): subjects, observations,
/// assessments, findings and events, and retires users missing from a complete /users list.
/// </summary>
public static class M365Evaluator
{
    private static readonly string[] TenantChecks = ["M365-003", "M365-004", "M365-005", "M365-006"];

    /// <param name="policy">The revision in effect now: the current projection is evaluated by it.</param>
    /// <param name="sourcePolicyVersion">The revision in effect when the run started (05 «Выбор текущего состояния»).</param>
    public static async Task WriteAsync(DbScope scope, CollectionRun run, Guid tenantId, CollectionOutcome outcome,
        PolicyRevision policy, int sourcePolicyVersion, DateTimeOffset now, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var configuration = JsonDocument.Parse(policy.Configuration).RootElement;
        var subjects = await scope.Db.Subjects
            .Where(s => s.OrganizationId == org && (s.Type == "tenant" || s.Type == "user"))
            .ToDictionaryAsync(s => (s.Type, s.Key), ct);
        var findings = await scope.Db.Findings.Where(f => f.OrganizationId == org && f.CheckId.StartsWith("M365-"))
            .ToDictionaryAsync(f => (f.SubjectId, f.CheckId), ct);
        var machine = new FindingMachine(scope.Db, org, now);

        Subject SubjectFor(string type, string key, string? display)
        {
            if (!subjects.TryGetValue((type, key), out var subject))
            {
                subject = new Subject
                {
                    OrganizationId = org, Id = Guid.CreateVersion7(), Type = type, Key = key, DisplayName = display,
                    FirstSeenAt = now, LastSeenAt = now,
                };
                scope.Db.Subjects.Add(subject);
                subjects[(type, key)] = subject;
            }
            subject.DisplayName = display ?? subject.DisplayName;
            subject.LastSeenAt = now;
            subject.RetiredAt = null;
            return subject;
        }

        var tenantSubject = SubjectFor("tenant", tenantId.ToString(), outcome.TenantDisplayName);
        var evaluated = new HashSet<(Guid, string)>();
        foreach (var item in outcome.Observations)
        {
            var checkId = item["checkId"]!.GetValue<string>();
            var subjectNode = item["subject"]!;
            var subject = subjectNode["type"]!.GetValue<string>() == "tenant"
                ? tenantSubject
                : SubjectFor("user", subjectNode["key"]!.GetValue<string>(), subjectNode["userPrincipalName"]?.GetValue<string>());
            var collected = item["collectionStatus"]!.GetValue<string>() == "collected";
            var observation = new Observation
            {
                OrganizationId = org, Id = Guid.CreateVersion7(), SubjectId = subject.Id, CheckId = checkId, Source = "graph",
                CollectionRunId = run.Id, ObservedAt = DateTimeOffset.Parse(item["observedAt"]!.GetValue<string>(),
                    System.Globalization.CultureInfo.InvariantCulture),
                ReceivedAt = now, CollectionStatus = collected ? "collected" : "unavailable",
                Evidence = collected ? item["evidence"]!.ToJsonString() : null,
                ReasonCode = collected ? null : item["reasonCode"]!.GetValue<string>(),
            };
            scope.Db.Observations.Add(observation);
            var input = new RuleInput(checkId, subject.Key, observation.CollectionStatus,
                collected ? JsonDocument.Parse(observation.Evidence!).RootElement : null, observation.ReasonCode, observation.ObservedAt);
            Evaluate(scope, machine, findings, subject, checkId, input, observation, policy, configuration, now,
                "source_change", sourcePolicyVersion);
            evaluated.Add((subject.Id, checkId));
        }

        // Active tenant checks without an observation in this run: unknown/missing_observation.
        var active = configuration.GetProperty("activeCheckIds").EnumerateArray().Select(e => e.GetString()!).ToHashSet();
        foreach (var checkId in TenantChecks.Where(active.Contains).Where(c => !evaluated.Contains((tenantSubject.Id, c))))
        {
            Evaluate(scope, machine, findings, tenantSubject, checkId, null, null, policy, configuration, now,
                "source_change", sourcePolicyVersion);
        }

        // A complete /users list retires users that left the tenant; an incomplete one retires nobody.
        if (outcome.UsersComplete)
        {
            var seen = outcome.SeenUserIds.Select(id => id.ToString()).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var subject in subjects.Values.Where(s => s.Type == "user" && s.RetiredAt is null && !seen.Contains(s.Key)))
            {
                subject.RetiredAt = now;
                foreach (var finding in findings.Values.Where(f => f.SubjectId == subject.Id))
                {
                    machine.Retire(finding, "source_change");
                }
            }
        }
    }

    private static void Evaluate(DbScope scope, FindingMachine machine, Dictionary<(Guid, string), Finding> findings,
        Subject subject, string checkId, RuleInput? input, Observation? observation, PolicyRevision policy,
        JsonElement configuration, DateTimeOffset now, string cause, int sourcePolicyVersion)
    {
        var outcome = RuleEngine.Evaluate(input, checkId, configuration);
        var mode = configuration.GetProperty("checks").GetProperty(checkId).GetProperty("assessmentMode").GetString()!;
        var assessment = new Data.Assessment
        {
            OrganizationId = scope.OrganizationId!.Value, Id = Guid.CreateVersion7(), ObservationId = observation?.Id,
            SubjectId = subject.Id, CheckId = checkId, RuleId = checkId, RuleVersion = RuleEngine.RuleVersion,
            SourcePolicyVersion = sourcePolicyVersion, EvaluatedPolicyVersion = policy.Version, AssessmentScope = "current",
            AssessmentMode = mode, Result = outcome.Result, Severity = outcome.Result == "fail" ? outcome.Severity : null,
            ReasonCode = outcome.ReasonCode, ObservedAt = observation?.ObservedAt ?? now,
            ReceivedAt = observation?.ReceivedAt ?? now, EvaluatedAt = now,
            BasisSnapshot = Snapshot(checkId, mode, policy.Version, outcome, observation?.ObservedAt ?? now),
        };
        scope.Db.Assessments.Add(assessment);
        findings.TryGetValue((subject.Id, checkId), out var finding);
        // Exclusion by excludedUserIds is a policy decision; the other not_applicable cases follow source facts.
        // In a recalculation every change comes from the new revision (policy_changed/policy_change).
        var bySource = cause == "source_change" && outcome.Result == "not_applicable"
                       && !outcome.Explanation.EndsWith(".excluded", StringComparison.Ordinal);
        machine.Apply(finding, assessment, cause, bySource);
        if (finding is null && scope.Db.ChangeTracker.Entries<Finding>()
                .FirstOrDefault(e => e.State == EntityState.Added && e.Entity.SubjectId == subject.Id && e.Entity.CheckId == checkId)
                is { } added)
        {
            findings[(subject.Id, checkId)] = added.Entity;
        }
    }

    /// <summary>Subjects of M365 checks that recalculate_policy processes per batch.</summary>
    public static readonly string[] SubjectTypes = ["tenant", "user"];

    /// <summary>
    /// recalculate_policy for a batch of subjects (05 «Выбор текущего состояния», steps 2–4): the current projection —
    /// the observation of the last completed or partial run with the subject — is evaluated by the newest revision and
    /// the current ruleVersion; a required (assessed) check without an observation gives unknown/missing_observation; an
    /// open finding of a check that left activeCheckIds becomes policy_changed. The cause is rule_change when only the
    /// ruleVersion changed since the last evaluation of the pair, otherwise policy_change. Pairs already evaluated by this
    /// revision and ruleVersion are skipped.
    /// </summary>
    public static async Task RecalculateAsync(DbScope scope, IReadOnlyList<Subject> subjects, PolicyRevision policy,
        DateTimeOffset now, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var ids = subjects.Select(s => s.Id).ToArray();
        var configuration = JsonDocument.Parse(policy.Configuration).RootElement;
        var active = configuration.GetProperty("activeCheckIds").EnumerateArray().Select(e => e.GetString()!).ToHashSet();
        var projections = new Dictionary<(Guid, string), (Observation Observation, int SourcePolicyVersion)>();
        var runs = await CollectionRuns.ProjectionRunsAsync(scope, ct);
        await using (var command = new NpgsqlCommand("""
            select distinct on (o.subject_id, o.check_id) o.id, o.subject_id, o.check_id, o.collection_run_id, o.observed_at,
                   o.received_at, o.collection_status, o.evidence::text, o.reason_code, coalesce(r.policy_version, 1)
            from observation o
            join unnest(@run_ids, @run_completed_at, @run_policy_versions) as r (id, completed_at, policy_version)
                on r.id = o.collection_run_id
            where o.organization_id = @org and o.subject_id = any(@subjects)
            order by o.subject_id, o.check_id, r.completed_at desc, o.id desc
            """, scope.Connection, scope.Transaction))
        {
            command.Parameters.AddWithValue("org", org);
            command.Parameters.AddWithValue("subjects", ids);
            command.Parameters.AddWithValue("run_ids", NpgsqlDbType.Array | NpgsqlDbType.Uuid, runs.Select(r => r.Id).ToArray());
            command.Parameters.AddWithValue("run_completed_at", NpgsqlDbType.Array | NpgsqlDbType.TimestampTz,
                runs.Select(r => r.CompletedAt).ToArray());
            command.Parameters.AddWithValue("run_policy_versions", NpgsqlDbType.Array | NpgsqlDbType.Integer,
                runs.Select(r => r.PolicyVersion).ToArray());
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var observation = new Observation
                {
                    OrganizationId = org, Id = reader.GetGuid(0), SubjectId = reader.GetGuid(1), CheckId = reader.GetString(2),
                    Source = "graph", CollectionRunId = reader.GetGuid(3), ObservedAt = reader.GetFieldValue<DateTimeOffset>(4),
                    ReceivedAt = reader.GetFieldValue<DateTimeOffset>(5), CollectionStatus = reader.GetString(6),
                    Evidence = reader.IsDBNull(7) ? null : reader.GetString(7), ReasonCode = reader.IsDBNull(8) ? null : reader.GetString(8),
                };
                projections[(observation.SubjectId, observation.CheckId)] = (observation, reader.GetInt32(9));
            }
        }
        var evaluated = new HashSet<(Guid, string, Guid?)>();
        var previous = new Dictionary<(Guid, string), (int PolicyVersion, string RuleVersion)>();
        await using (var command = new NpgsqlCommand("""
            select distinct on (subject_id, check_id) subject_id, check_id, observation_id, evaluated_policy_version, rule_version
            from assessment
            where organization_id = @org and subject_id = any(@subjects) and assessment_scope = 'current'
            order by subject_id, check_id, evaluated_at desc, id desc
            """, scope.Connection, scope.Transaction))
        {
            command.Parameters.AddWithValue("org", org);
            command.Parameters.AddWithValue("subjects", ids);
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                previous[(reader.GetGuid(0), reader.GetString(1))] = (reader.GetInt32(3), reader.GetString(4));
                if (reader.GetInt32(3) == policy.Version && reader.GetString(4) == RuleEngine.RuleVersion)
                {
                    evaluated.Add((reader.GetGuid(0), reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetGuid(2)));
                }
            }
        }
        var findings = await scope.Db.Findings.Where(f => f.OrganizationId == org && ids.Contains(f.SubjectId))
            .ToDictionaryAsync(f => (f.SubjectId, f.CheckId), ct);
        var machine = new FindingMachine(scope.Db, org, now);
        foreach (var subject in subjects)
        {
            foreach (var check in Catalog.Checks.Where(c => c.Source == "graph" && c.SubjectType == subject.Type))
            {
                findings.TryGetValue((subject.Id, check.CheckId), out var finding);
                if (!active.Contains(check.CheckId))
                {
                    if (finding is not null)
                    {
                        machine.PolicyRemoved(finding);
                    }
                    continue;
                }
                var hasProjection = projections.TryGetValue((subject.Id, check.CheckId), out var projection);
                // Without an observation only a required check gets unknown/missing_observation; M365-002 has subjects
                // only where the collector reported a privileged role.
                var mode = configuration.GetProperty("checks").GetProperty(check.CheckId).GetProperty("assessmentMode").GetString();
                if (!hasProjection && (check.CheckId == "M365-002" || mode != "assessed"))
                {
                    continue;
                }
                var observation = hasProjection ? projection.Observation : null;
                if (evaluated.Contains((subject.Id, check.CheckId, observation?.Id)))
                {
                    continue;
                }
                var input = observation is null ? null : new RuleInput(check.CheckId, subject.Key, observation.CollectionStatus,
                    observation.Evidence is null ? null : JsonDocument.Parse(observation.Evidence).RootElement, observation.ReasonCode,
                    observation.ObservedAt);
                var cause = previous.TryGetValue((subject.Id, check.CheckId), out var last) && last.PolicyVersion == policy.Version
                            && last.RuleVersion != RuleEngine.RuleVersion
                    ? "rule_change"
                    : "policy_change";
                Evaluate(scope, machine, findings, subject, check.CheckId, input, observation, policy, configuration, now,
                    cause, hasProjection ? projection.SourcePolicyVersion : policy.Version);
            }
        }
    }

    internal static string Snapshot(string checkId, string mode, int policyVersion, RuleOutcome outcome, DateTimeOffset observedAt)
    {
        var node = new JsonObject
        {
            ["checkId"] = checkId, ["ruleId"] = checkId, ["ruleVersion"] = RuleEngine.RuleVersion,
            ["evaluatedPolicyVersion"] = policyVersion, ["assessmentMode"] = mode, ["result"] = outcome.Result,
            ["severity"] = outcome.Result == "fail" ? outcome.Severity : null, ["reasonCode"] = outcome.ReasonCode,
            ["observedAt"] = UtcTimeConverter.Format(observedAt), ["explanation"] = outcome.Explanation,
            ["arguments"] = outcome.Arguments is null ? null
                : new JsonObject(outcome.Arguments.Select(a => KeyValuePair.Create(a.Key, (JsonNode?)a.Value))),
        };
        return node.ToJsonString();
    }

    /// <summary>Users that had a privileged role in the previous complete collection (for M365-002 «роль снята»).</summary>
    public static async Task<HashSet<Guid>> PreviouslyPrivilegedAsync(DbScope scope, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var keys = await scope.Db.Database.SqlQuery<string>($"""
            select s.key as "Value"
            from finding f join subject s on s.organization_id = f.organization_id and s.id = f.subject_id
            where f.organization_id = {org} and f.check_id = 'M365-002' and s.retired_at is null
            union
            select s.key
            from subject s
            join lateral (
                select o.evidence from observation o
                where o.organization_id = s.organization_id and o.subject_id = s.id and o.check_id = 'M365-002'
                order by o.observed_at desc limit 1) last on true
            where s.organization_id = {org} and s.type = 'user' and s.retired_at is null
              and last.evidence is not null and jsonb_array_length(last.evidence -> 'roleTemplateIds') > 0
            """).ToListAsync(ct);
        return keys.Select(Guid.Parse).ToHashSet();
    }

    public static string Capabilities(IReadOnlyDictionary<string, string> modules) =>
        new JsonArray(Catalog.GraphModules.Select(m => (JsonNode)new JsonObject
        {
            ["module"] = m, ["status"] = modules.GetValueOrDefault(m, "skipped"),
        }).ToArray()).ToJsonString();
}
