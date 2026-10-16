using System.Text.Json;
using System.Text.Json.Nodes;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Organizations;

/// <summary>
/// Policy v1 from the defaults of PolicyConfiguration and the rules beyond the schema (05 «Политика клиента»):
/// 422 policy_inputs_missing and 422 validation_failed.
/// </summary>
public sealed class PolicyRules
{
    private readonly string _defaults;

    public PolicyRules(ContractSchemas schemas)
    {
        var schema = schemas.Api.GetProperty("components").GetProperty("schemas").GetProperty("PolicyConfiguration");
        _defaults = Defaults(schema)!.ToJsonString();
    }

    /// <summary>Configuration of policy v1: the default values of the schema.</summary>
    public string DefaultConfiguration => _defaults;

    public static void Validate(JsonElement configuration)
    {
        var active = configuration.GetProperty("activeCheckIds").EnumerateArray().Select(e => e.GetString()!).ToHashSet();
        var checks = configuration.GetProperty("checks");
        var missing = new List<string>();
        if (!active.Contains("WIN-011"))
        {
            missing.Add("WIN-011 must be in activeCheckIds");
        }
        if (active.Contains("WIN-004") && !active.Contains("WIN-003"))
        {
            missing.Add("WIN-004 requires WIN-003");
        }
        if (Mode(checks, "WIN-003") == "assessed")
        {
            var parameters = checks.GetProperty("WIN-003").GetProperty("parameters");
            if (parameters.GetProperty("approvedProviders").GetArrayLength() == 0
                && !parameters.GetProperty("defenderApproved").GetBoolean())
            {
                missing.Add("WIN-003 assessed needs approvedProviders or defenderApproved");
            }
        }
        if (Mode(checks, "WIN-010") == "assessed"
            && checks.GetProperty("WIN-010").GetProperty("parameters").GetProperty("expectedTenantId").ValueKind == JsonValueKind.Null)
        {
            missing.Add("WIN-010 assessed needs expectedTenantId");
        }
        // M365-007 is deferred: it is not collected, so «assessed» would give every user unknown/missing_observation (05).
        foreach (var deferred in Catalog.DeferredIds.Where(id => Mode(checks, id) == "assessed"))
        {
            missing.Add(deferred + " is not collected yet and can only be informational");
        }
        if (missing.Count > 0)
        {
            throw new ApiProblemException(ProblemCodes.PolicyInputsMissing, string.Join("; ", missing));
        }

        var invalid = new List<string>();
        var agent = configuration.GetProperty("agent");
        if (agent.GetProperty("maxBatchAgeDays").GetInt32() < agent.GetProperty("maxBufferDays").GetInt32() + 1)
        {
            invalid.Add("maxBatchAgeDays must be at least maxBufferDays + 1");
        }
        var admins = checks.GetProperty("M365-005").GetProperty("parameters");
        if (admins.GetProperty("minGlobalAdmins").GetInt32() > admins.GetProperty("maxGlobalAdmins").GetInt32())
        {
            invalid.Add("minGlobalAdmins must not exceed maxGlobalAdmins");
        }
        var disk = checks.GetProperty("WIN-001").GetProperty("parameters");
        if (disk.GetProperty("warnFreePercent").GetInt32() < disk.GetProperty("criticalFreePercent").GetInt32()
            || disk.GetProperty("warnFreeBytes").GetInt64() < disk.GetProperty("criticalFreeBytes").GetInt64())
        {
            invalid.Add("WIN-001 warning thresholds must not be stricter than critical");
        }
        var signatures = checks.GetProperty("WIN-004").GetProperty("parameters");
        if (signatures.GetProperty("warnDays").GetInt32() > signatures.GetProperty("criticalDays").GetInt32())
        {
            invalid.Add("WIN-004 warnDays must not exceed criticalDays");
        }
        if (invalid.Count > 0)
        {
            throw new ApiProblemException(ProblemCodes.ValidationFailed, string.Join("; ", invalid));
        }
    }

    private static string Mode(JsonElement checks, string checkId) =>
        checks.GetProperty(checkId).GetProperty("assessmentMode").GetString()!;

    private static JsonNode? Defaults(JsonElement schema)
    {
        if (schema.TryGetProperty("default", out var value))
        {
            return JsonNode.Parse(value.GetRawText());
        }
        if (!schema.TryGetProperty("properties", out var properties))
        {
            return null;
        }
        var result = new JsonObject();
        foreach (var name in schema.GetProperty("required").EnumerateArray().Select(n => n.GetString()!))
        {
            result[name] = Defaults(properties.GetProperty(name));
        }
        return result;
    }
}
