using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Agents;

/// <summary>
/// submitScan (05 «Порядок приёма пакета»): the checks run in the order of the table and the first refusal answers. The row
/// of the device is locked for the whole intake, so concurrent repeats of one scanId see each other (step 12), and the
/// batch, its observations, assessments, findings and events are written in one transaction before the receipt is sent.
/// </summary>
public static partial class ScanIntake
{
    public const string SchemaVersion = "2.0";
    public const string SentAtHeader = "Sikkerheit-Sent-At";
    private static readonly string[] AgentChecks = Catalog.Checks.Where(c => c.Source == "agent").Select(c => c.CheckId).ToArray();

    [GeneratedRegex(@"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$")]
    private static partial Regex UtcTime();

    private sealed record Parsed(
        Guid ScanId, long Sequence, string AgentVersion, int PolicyVersion, string Fingerprint, DateTimeOffset StartedAt,
        DateTimeOffset CompletedAt, Guid? ScanRequestId, List<ScanObservation> Observations);

    public static async Task<IResult> SubmitAsync(HttpContext http, DbScopes scopes, ContractSchemas schemas, AgentOptions options,
        TimeProvider clock, CancellationToken ct)
    {
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        AgentContext? context = null;
        try
        {
            var result = await SubmitCoreAsync(http, scopes, schemas, options, clock, ct, c => context = c);
            AgentMetrics.Batch(context!.OrganizationId, context.DeviceId, "accepted", System.Diagnostics.Stopwatch.GetElapsedTime(started));
            return result;
        }
        catch (ApiProblemException problem) when (context is not null)
        {
            AgentMetrics.Batch(context.OrganizationId, context.DeviceId, problem.Code, System.Diagnostics.Stopwatch.GetElapsedTime(started));
            throw;
        }
    }

    private static async Task<IResult> SubmitCoreAsync(HttpContext http, DbScopes scopes, ContractSchemas schemas, AgentOptions options,
        TimeProvider clock, CancellationToken ct, Action<AgentContext> authenticated)
    {
        // 1. The token and the statuses.
        var context = await AgentRequests.AuthenticateAsync(http, scopes, clock, ct);
        authenticated(context);
        // 2–3. Media type, size, JSON.
        var (bytes, json) = await RequestBodies.ReadJsonAsync(http, AgentOptions.MaxBatchBytes);
        var receivedAt = clock.GetUtcNow();
        var payloadHash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes));
        // 4. The version of the agent comes before the schema, so that an agent of a retired schema is stopped, not rejected.
        if (json.ValueKind == JsonValueKind.Object && json.TryGetProperty("agentVersion", out var versionNode)
            && versionNode.ValueKind == JsonValueKind.String
            && AgentVersions.Compare(versionNode.GetString()!, options.MinimumAgentVersion) < 0)
        {
            throw new ApiProblemException(ProblemCodes.AgentVersionUnsupported, extensions: new Dictionary<string, object?>
            {
                ["minimumAgentVersion"] = options.MinimumAgentVersion,
            });
        }
        // 5. The schema version, the schema and the headers.
        if (json.ValueKind == JsonValueKind.Object && json.TryGetProperty("schemaVersion", out var schemaNode)
            && schemaNode.ValueKind == JsonValueKind.String && schemaNode.GetString() != SchemaVersion)
        {
            throw new ApiProblemException(ProblemCodes.UnsupportedSchemaVersion);
        }
        // A subject of the wrong type for its check is a refusal of step 11 (unexpected_subject), not of the schema: the schema
        // is checked with such a subject put right, and the mistake is raised in its place.
        var (checked_, wrongType) = WithSubjectTypesPutRight(json);
        var violations = schemas.ValidateComponent("ScanBatch", checked_);
        if (violations.Count > 0)
        {
            throw new ApiProblemException(ProblemCodes.SchemaViolation, $"{violations[0].InstanceLocation} {violations[0].Message}".Trim());
        }
        if (!http.Request.Headers.TryGetValue(SentAtHeader, out var sentHeader) || !UtcTime().IsMatch(sentHeader.ToString())
            || !DateTimeOffset.TryParse(sentHeader.ToString(), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var sentAt))
        {
            throw new ApiProblemException(ProblemCodes.SchemaViolation, SentAtHeader + " is missing or not a UTC date-time");
        }
        var batch = Parse(json);
        if (!http.Request.Headers.TryGetValue("Idempotency-Key", out var keyHeader) || !Guid.TryParse(keyHeader.ToString(), out var key)
            || key != batch.ScanId)
        {
            throw new ApiProblemException(ProblemCodes.SchemaViolation, "Idempotency-Key must equal scanId");
        }
        foreach (var item in batch.Observations.Where(o => o.CheckId == "WIN-001" && o.CollectionStatus == "collected"))
        {
            if (item.Evidence!.Value.GetProperty("freeBytes").GetInt64() > item.Evidence!.Value.GetProperty("totalBytes").GetInt64())
            {
                throw new ApiProblemException(ProblemCodes.SchemaViolation, "WIN-001 freeBytes is greater than totalBytes");
            }
        }

        await using var scope = await scopes.OrganizationAsync(context.OrganizationId, ct);
        var org = context.OrganizationId;
        var device = await Devices.FindAsync(scope, context.DeviceId, forUpdate: true, ct)
            ?? throw new ApiProblemException(ProblemCodes.SessionInvalid);
        AgentRequests.RequireUsable(device, await OrganizationLifecycle.FindAsync(scope, forUpdate: false, ct));

        // 6. The same scanId: the same bytes get the first receipt, other bytes are a conflict (under the lock of the device).
        var existing = await scope.Db.ScanBatches.AsNoTracking().SingleOrDefaultAsync(
            b => b.OrganizationId == org && b.DeviceId == device.Id && b.ScanId == batch.ScanId, ct);
        if (existing is not null)
        {
            return existing.PayloadHash == payloadHash ? Receipt(existing, duplicate: true) : throw new ApiProblemException(ProblemCodes.IdempotencyConflict);
        }
        // 7. The machine is another one.
        var fingerprint = AgentCrypto.Sha256Hex(batch.Fingerprint);
        if (fingerprint != device.MachineFingerprintHash)
        {
            Devices.MarkConflict(device, "fingerprint", receivedAt, fingerprint, null, null);
            AuditLog.Device(scope, device.Id, "device.identity_conflict", "device", device.Id.ToString(), http.TraceIdentifier);
            await scope.CommitAsync(ct);
            throw new ApiProblemException(ProblemCodes.IdentityConflict, "conflictKind=fingerprint");
        }
        Devices.RecoverIdentity(device, receivedAt);
        // 8. The times of the batch agree with each other.
        if (batch.CompletedAt < batch.StartedAt
            || batch.Observations.Any(o => o.ObservedAt < batch.StartedAt || o.ObservedAt > batch.CompletedAt))
        {
            throw new ApiProblemException(ProblemCodes.BatchTimeInconsistent);
        }
        // 9. Too old by the clock of the PC.
        var current = await Policies.CurrentAsync(scope, ct) ?? throw new InvalidOperationException("Organization has no policy revision");
        using var currentDocument = JsonDocument.Parse(current.Configuration);
        var maxAgeDays = currentDocument.RootElement.GetProperty("agent").GetProperty("maxBatchAgeDays").GetInt32();
        if (sentAt - batch.CompletedAt > TimeSpan.FromDays(maxAgeDays))
        {
            throw new ApiProblemException(ProblemCodes.BatchTooOld);
        }
        // 10. The policy version exists.
        var source = batch.PolicyVersion > current.Version ? null : await Policies.GetAsync(scope, batch.PolicyVersion, ct);
        if (source is null)
        {
            throw new ApiProblemException(ProblemCodes.UnknownPolicyVersion);
        }
        // 11. Duplicates, checks that are not active in the policy of the batch, subjects of the wrong type.
        using var sourceDocument = JsonDocument.Parse(source.Configuration);
        var active = sourceDocument.RootElement.GetProperty("activeCheckIds").EnumerateArray().Select(e => e.GetString()!).ToHashSet();
        var keys = new HashSet<(string, string, string)>();
        foreach (var item in batch.Observations)
        {
            if (!keys.Add((item.CheckId, item.SubjectType, item.VolumeId ?? "device")))
            {
                throw new ApiProblemException(ProblemCodes.DuplicateObservation);
            }
        }
        if (wrongType || batch.Observations.Any(o => !active.Contains(o.CheckId)
                                                    || o.SubjectType != Catalog.Check(o.CheckId).SubjectType))
        {
            throw new ApiProblemException(ProblemCodes.UnexpectedSubject);
        }
        // 12. The order of the batches of the device.
        if (batch.Sequence <= device.LastAcceptedSequence)
        {
            AuditLog.Device(scope, device.Id, "device.sequence_resync", "device", device.Id.ToString(), http.TraceIdentifier);
            await scope.CommitAsync(ct);
            throw new ApiProblemException(ProblemCodes.SequenceConflict);
        }

        var clockInconsistent = ClockInconsistent(batch, sentAt, receivedAt);
        var full = !clockInconsistent && AgentChecks.Where(active.Contains).All(id => batch.Observations.Any(o => o.CheckId == id));
        var replaces = !clockInconsistent && (device.ProjectionCompletedAt is null || batch.CompletedAt >= device.ProjectionCompletedAt);
        var row = new ScanBatch
        {
            OrganizationId = org, DeviceId = device.Id, Id = Guid.CreateVersion7(), ScanId = batch.ScanId, Sequence = batch.Sequence,
            PolicyVersion = batch.PolicyVersion, StartedAt = batch.StartedAt, CompletedAt = batch.CompletedAt, SentAt = sentAt,
            ReceivedAt = receivedAt, PayloadHash = payloadHash, ClockInconsistent = clockInconsistent, IsFull = full,
            ReplacedProjection = replaces,
        };
        scope.Db.ScanBatches.Add(row);
        await scope.Db.SaveChangesAsync(ct);

        device.LastAcceptedSequence = batch.Sequence;
        device.LastSeenAt = receivedAt;
        device.AgentVersion = batch.AgentVersion;
        device.ClockStatus = clockInconsistent ? "inconsistent" : "ok";
        if (full)
        {
            device.LastFullScanAt = device.LastFullScanAt is { } last && last > batch.CompletedAt ? last : batch.CompletedAt;
        }
        var intake = new IntakeBatch(row.Id, batch.CompletedAt, receivedAt, batch.PolicyVersion, clockInconsistent, replaces, full,
            receivedAt, device.LastFullScanAt);
        var catalog = await ReleaseCatalogStore.ViewAsync(scope, ct);
        var episode = await WindowsEvaluator.IngestAsync(scope, Devices.State(device), intake, batch.Observations, current, source, catalog, ct);
        if (replaces)
        {
            device.ProjectionSequence = batch.Sequence;
            device.ProjectionCompletedAt = batch.CompletedAt;
            device.RebootEpisodeSince = episode.Since;
            device.RebootEpisodeBootAt = episode.BootAt;
        }
        await Devices.MarkPresentAsync(scope, device.Id, receivedAt, ct);
        await DeviceSubjects.SeenAsync(scope, device.Id, receivedAt, ct);
        if (batch.ScanRequestId is { } requestId)
        {
            // A request of another device or an expired one is ignored (the batch is an ordinary scan).
            var request = await scope.Db.ScanRequests.SingleOrDefaultAsync(
                r => r.OrganizationId == org && r.Id == requestId && r.DeviceId == device.Id, ct);
            if (request is { State: "requested" or "delivered" } && request.ExpiresAt > receivedAt)
            {
                request.State = "completed";
            }
            else
            {
                http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Sikkerheit.Agents")
                    .LogInformation("scanRequestId {ScanRequestId} of a batch is not an open request of device {DeviceId}", requestId, device.Id);
            }
        }
        try
        {
            await scope.CommitAsync(ct);
        }
        catch (DbUpdateException error) when (error.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            // Two intakes of one device cannot overlap under the row lock; a unique violation here is a repeat of the sequence.
            throw new ApiProblemException(ProblemCodes.SequenceConflict);
        }
        return Receipt(row, duplicate: false);
    }

    /// <summary>
    /// The batch with the subject of every observation whose type does not fit its check replaced by a valid one of the
    /// right type, and whether there was such an observation.
    /// </summary>
    private static (JsonElement Batch, bool WrongType) WithSubjectTypesPutRight(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("observations", out var list) || list.ValueKind != JsonValueKind.Array)
        {
            return (root, false);
        }
        var node = System.Text.Json.Nodes.JsonNode.Parse(root.GetRawText())!;
        var wrong = false;
        foreach (var observation in node["observations"]!.AsArray())
        {
            if (observation is not System.Text.Json.Nodes.JsonObject item || item["checkId"] is not { } id
                || id.GetValueKind() != JsonValueKind.String || !Catalog.Checks.Any(c => c.CheckId == id.GetValue<string>())
                || item["subject"] is not System.Text.Json.Nodes.JsonObject subject || subject["type"] is not { } type
                || type.GetValueKind() != JsonValueKind.String)
            {
                continue;
            }
            var expected = Catalog.Check(id.GetValue<string>()).SubjectType;
            if (type.GetValue<string>() == expected)
            {
                continue;
            }
            wrong = true;
            item["subject"] = expected == "volume"
                ? System.Text.Json.Nodes.JsonNode.Parse("""{"type":"volume","volumeId":"\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\","role":"os"}""")
                : System.Text.Json.Nodes.JsonNode.Parse("""{"type":"device"}""");
        }
        return (JsonDocument.Parse(node.ToJsonString()).RootElement, wrong);
    }

    /// <summary>The clock flag (05 «Время и часы устройства»): any label of the batch more than 5 minutes off the server time.</summary>
    public static bool ClockInconsistent(DateTimeOffset completedAt, DateTimeOffset startedAt, IEnumerable<DateTimeOffset> observed,
        DateTimeOffset sentAt, DateTimeOffset receivedAt)
    {
        var tolerance = AgentRequests.ClockTolerance;
        return (sentAt - receivedAt).Duration() > tolerance || completedAt - sentAt > tolerance || completedAt > receivedAt + tolerance
               || startedAt > receivedAt + tolerance || observed.Any(o => o > receivedAt + tolerance);
    }

    private static bool ClockInconsistent(Parsed batch, DateTimeOffset sentAt, DateTimeOffset receivedAt) =>
        ClockInconsistent(batch.CompletedAt, batch.StartedAt, batch.Observations.Select(o => o.ObservedAt), sentAt, receivedAt);

    private static IResult Receipt(ScanBatch batch, bool duplicate) => Results.Json(new
    {
        scanId = batch.ScanId, sequence = batch.Sequence, acceptedAt = batch.ReceivedAt, duplicate,
        clockInconsistent = batch.ClockInconsistent,
    }, ApiJson.Options);

    private static DateTimeOffset Time(JsonElement node) => DateTimeOffset.Parse(node.GetString()!, CultureInfo.InvariantCulture,
        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

    private static Parsed Parse(JsonElement root) => ParseLoosely(root);

    /// <summary>Reads a batch whose subjects may have the wrong shape for their check; the other fields are required.</summary>
    private static Parsed ParseLoosely(JsonElement root)
    {
        try
        {
            var observations = new List<ScanObservation>();
            foreach (var node in root.GetProperty("observations").EnumerateArray())
            {
                var subject = node.GetProperty("subject");
                var type = subject.TryGetProperty("type", out var typeNode) && typeNode.ValueKind == JsonValueKind.String
                    ? typeNode.GetString()! : "?";
                var collected = node.GetProperty("collectionStatus").GetString() == "collected";
                observations.Add(new ScanObservation(node.GetProperty("checkId").GetString()!, type,
                    type == "volume" && subject.TryGetProperty("volumeId", out var volume) && volume.ValueKind == JsonValueKind.String
                        ? volume.GetString() : null,
                    subject.TryGetProperty("mountPoint", out var mount) && mount.ValueKind == JsonValueKind.String ? mount.GetString() : null,
                    Time(node.GetProperty("observedAt")), node.GetProperty("collectionStatus").GetString()!,
                    collected ? node.GetProperty("evidence").Clone() : null,
                    collected ? null : node.GetProperty("reasonCode").GetString()));
            }
            return new Parsed(Guid.Parse(root.GetProperty("scanId").GetString()!), root.GetProperty("sequence").GetInt64(),
                root.GetProperty("agentVersion").GetString()!, root.GetProperty("policyVersion").GetInt32(),
                root.GetProperty("machineFingerprint").GetString()!, Time(root.GetProperty("startedAt")),
                Time(root.GetProperty("completedAt")),
                root.TryGetProperty("scanRequestId", out var request) && request.ValueKind == JsonValueKind.String
                    && Guid.TryParse(request.GetString(), out var requestId) ? requestId : null, observations);
        }
        catch (Exception error) when (error is KeyNotFoundException or InvalidOperationException or FormatException)
        {
            throw new ApiProblemException(ProblemCodes.SchemaViolation, "the batch does not match its schema");
        }
    }
}
