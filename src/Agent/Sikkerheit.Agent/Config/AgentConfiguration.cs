using System.Globalization;
using System.Text.Json;
using Sikkerheit.Contracts;

namespace Sikkerheit.Agent.Config;

/// <summary>Configuration of the server (05, "API агента"): schedule, list of checks, limits and the flag of a repeated scan. No commands.</summary>
public sealed record AgentConfiguration(
    int ConfigSchemaVersion,
    int PolicyVersion,
    IReadOnlyList<string> ActiveCheckIds,
    int ScanIntervalHours,
    int CheckInIntervalHours,
    int ScanJitterMinutes,
    int MaxBatchBytes,
    long MaxBufferBytes,
    int MaxBufferDays,
    long LastAcceptedSequence,
    DateTimeOffset? LastAcceptedCompletedAt,
    string MinimumAgentVersion,
    string? PendingScanRequestId,
    DateTimeOffset ServerTime);

/// <summary>Strict parsing by the schema of the version of this agent: a field outside the schema rejects the whole configuration.</summary>
public sealed class ConfigurationParser(ContractSchemas schemas)
{
    /// <summary>Version of the configuration schema which this agent implements (a part of check-in).</summary>
    public const int SchemaVersion = 1;

    public bool TryParse(JsonElement body, out AgentConfiguration? configuration, out string error)
    {
        configuration = null;
        var violations = schemas.ValidateComponent("Configuration", body);
        if (violations.Count > 0)
        {
            error = string.Join("; ", violations.Select(v => $"{v.InstanceLocation}: {v.Message}"));
            return false;
        }
        if (body.GetProperty("configSchemaVersion").GetInt32() != SchemaVersion)
        {
            error = "configSchemaVersion differs from the version of the agent";
            return false;
        }
        configuration = new AgentConfiguration(
            body.GetProperty("configSchemaVersion").GetInt32(),
            body.GetProperty("policyVersion").GetInt32(),
            body.GetProperty("activeCheckIds").EnumerateArray().Select(e => e.GetString()!).ToList(),
            body.GetProperty("scanIntervalHours").GetInt32(),
            body.GetProperty("checkInIntervalHours").GetInt32(),
            body.GetProperty("scanJitterMinutes").GetInt32(),
            body.GetProperty("maxBatchBytes").GetInt32(),
            body.GetProperty("maxBufferBytes").GetInt64(),
            body.GetProperty("maxBufferDays").GetInt32(),
            body.GetProperty("lastAcceptedSequence").GetInt64(),
            Time(body.GetProperty("lastAcceptedCompletedAt")),
            body.GetProperty("minimumAgentVersion").GetString()!,
            body.GetProperty("pendingScanRequestId") is { ValueKind: JsonValueKind.String } id ? id.GetString() : null,
            Time(body.GetProperty("serverTime"))!.Value);
        error = "";
        return true;
    }

    private static DateTimeOffset? Time(JsonElement value) => value.ValueKind == JsonValueKind.String
        ? DateTimeOffset.Parse(value.GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal)
        : null;
}

/// <summary>Versions of the form x.y.z[-suffix]; the suffix is ignored when comparing.</summary>
public static class AgentVersion
{
    public static int Compare(string left, string right) => Parse(left).CompareTo(Parse(right));

    private static Version Parse(string text)
    {
        var core = text.Split('-', '+')[0];
        return Version.Parse(core);
    }
}
