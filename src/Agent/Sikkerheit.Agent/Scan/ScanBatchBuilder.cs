using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Sikkerheit.Agent.Collectors;
using Sikkerheit.Agent.Collectors.Mapping;
using Sikkerheit.Agent.Collectors.Runtime;
using Sikkerheit.Agent.Config;
using Sikkerheit.Contracts;

namespace Sikkerheit.Agent.Scan;

/// <summary>A built batch: the id, the sequence and the bytes that are stored and sent.</summary>
public sealed record BuiltBatch(string ScanId, long Sequence, DateTimeOffset CompletedAt, byte[] Body);

/// <summary>
/// Builds the batch of a full collection and checks every observation by the embedded schema before it is stored (02): an invalid
/// observation, including an unknown value of an enumeration, is replaced with unavailable/unsupported and the other checks are kept.
/// </summary>
public sealed class ScanBatchBuilder(ContractSchemas schemas, ILogger<ScanBatchBuilder> log)
{
    public const string SchemaVersion = "2.0";

    public BuiltBatch? Build(
        AgentConfiguration configuration, IReadOnlyList<CollectedItem> items, VolumeRef? osVolume, string machineFingerprint,
        string agentVersion, long sequence, DateTimeOffset startedAt, DateTimeOffset completedAt, string? scanRequestId)
    {
        var observations = new JsonArray();
        foreach (var item in items)
        {
            var observedAt = Clamp(item.ObservedAt, startedAt, completedAt);
            var subject = Subject(item.Collector.CheckId, osVolume);
            if (subject is null)
            {
                // No OS volume: the pair is absent, and the server answers unknown/missing_observation (03).
                log.LogWarning("Volume of the OS is unknown, {CheckId} is skipped", item.Collector.CheckId);
                continue;
            }
            observations.Add(Guard(item, subject, observedAt));
        }
        if (observations.Count == 0)
        {
            return null;
        }
        var scanId = Guid.NewGuid().ToString("D");
        var batch = new JsonObject
        {
            ["schemaVersion"] = SchemaVersion,
            ["scanId"] = scanId,
            ["sequence"] = sequence,
            ["agentVersion"] = agentVersion,
            ["policyVersion"] = configuration.PolicyVersion,
            ["machineFingerprint"] = machineFingerprint,
            ["startedAt"] = Iso.Format(startedAt),
            ["completedAt"] = Iso.Format(completedAt),
            ["scanRequestId"] = scanRequestId,
            ["observations"] = observations,
        };
        var bytes = Encoding.UTF8.GetBytes(batch.ToJsonString());
        using var document = JsonDocument.Parse(bytes);
        var violations = schemas.ValidateStandalone("scan-batch.schema.json", document.RootElement);
        if (violations.Count > 0)
        {
            log.LogError("The batch does not match scan-batch.schema.json and is dropped: {Violations}",
                string.Join("; ", violations.Select(v => $"{v.InstanceLocation} {v.Message}")));
            return null;
        }
        if (bytes.Length > configuration.MaxBatchBytes)
        {
            log.LogError("The batch is {Bytes} bytes, more than maxBatchBytes {Limit}; dropped", bytes.Length, configuration.MaxBatchBytes);
            return null;
        }
        return new BuiltBatch(scanId, sequence, completedAt, bytes);
    }

    /// <summary>Observation for the item; the invalid one becomes unavailable/unsupported.</summary>
    internal JsonObject Guard(CollectedItem item, JsonObject subject, DateTimeOffset observedAt)
    {
        var observation = Observation(item, subject, observedAt);
        var problem = Problem(observation);
        if (problem is null)
        {
            return observation;
        }
        log.LogWarning("Observation {CheckId} is replaced with unavailable/unsupported: {Problem}", item.Collector.CheckId, problem);
        return Observation(
            new CollectedItem(item.Collector, CollectorOutcome.Unavailable(ReasonCodes.Unsupported), item.ObservedAt), subject, observedAt);
    }

    private string? Problem(JsonObject observation)
    {
        using var document = JsonDocument.Parse(observation.ToJsonString());
        var violations = schemas.ValidateStandalone("observation.schema.json", document.RootElement);
        if (violations.Count > 0)
        {
            return string.Join("; ", violations.Select(v => $"{v.InstanceLocation} {v.Message}").Take(3));
        }
        // Cross-field rule outside the JSON Schema: freeBytes must not exceed totalBytes (05, "Порядок приёма пакета").
        if (observation["checkId"]!.GetValue<string>() == "WIN-001"
            && observation["evidence"] is JsonObject evidence
            && evidence["freeBytes"]!.GetValue<long>() > evidence["totalBytes"]!.GetValue<long>())
        {
            return "freeBytes is greater than totalBytes";
        }
        return null;
    }

    private static JsonObject Observation(CollectedItem item, JsonObject subject, DateTimeOffset observedAt)
    {
        var observation = new JsonObject
        {
            ["checkId"] = item.Collector.CheckId,
            ["collectorVersion"] = item.Collector.CollectorVersion,
            ["subject"] = subject.DeepClone(),
            ["observedAt"] = Iso.Format(observedAt),
        };
        if (item.Outcome.Evidence is { } evidence)
        {
            observation["collectionStatus"] = "collected";
            observation["evidence"] = evidence.DeepClone();
        }
        else
        {
            observation["collectionStatus"] = "unavailable";
            observation["reasonCode"] = item.Outcome.ReasonCode ?? ReasonCodes.TemporaryError;
        }
        return observation;
    }

    private static JsonObject? Subject(string checkId, VolumeRef? volume)
    {
        if (Catalog.Check(checkId).SubjectType != "volume")
        {
            return new JsonObject { ["type"] = "device" };
        }
        if (volume is null)
        {
            return null;
        }
        var subject = new JsonObject { ["type"] = "volume", ["volumeId"] = volume.VolumeId };
        if (volume.MountPoint is not null)
        {
            subject["mountPoint"] = volume.MountPoint;
        }
        subject["role"] = "os";
        return subject;
    }

    private static DateTimeOffset Clamp(DateTimeOffset value, DateTimeOffset from, DateTimeOffset to) =>
        value < from ? from : value > to ? to : value;
}
