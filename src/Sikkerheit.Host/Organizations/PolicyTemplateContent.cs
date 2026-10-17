using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Organizations;

/// <summary>The schema allowlists portable fields. Identity lists, tenant binding, editions and schedules never merge.</summary>
public static class PolicyTemplateContent
{
    public static JsonElement Merge(ContractSchemas schemas, JsonElement current, JsonElement content)
    {
        if (schemas.ValidateComponent("PolicyTemplateContent", content).Count != 0)
        {
            throw new ApiProblemException(ProblemCodes.SchemaViolation, "invalid portable template content");
        }
        var result = JsonNode.Parse(current.GetRawText())!.AsObject();
        var checks = content.GetProperty("checks");
        var selected = content.GetProperty("activeCheckIds").EnumerateArray().Select(x => x.GetString()!).ToHashSet();
        var active = result["activeCheckIds"]!.AsArray().Select(x => x!.GetValue<string>())
            .Where(id => !checks.TryGetProperty(id, out _) || selected.Contains(id)).ToList();
        active.AddRange(selected.Where(id => !active.Contains(id)).Order(StringComparer.Ordinal));
        result["activeCheckIds"] = new JsonArray(active.Select(id => (JsonNode?)JsonValue.Create(id)).ToArray());
        foreach (var check in checks.EnumerateObject())
        {
            var target = result["checks"]![check.Name]!.AsObject();
            target["assessmentMode"] = JsonNode.Parse(check.Value.GetProperty("assessmentMode").GetRawText());
            target["freshnessWindowHours"] = JsonNode.Parse(check.Value.GetProperty("freshnessWindowHours").GetRawText());
            foreach (var parameter in check.Value.GetProperty("parameters").EnumerateObject())
            {
                target["parameters"]![parameter.Name] = JsonNode.Parse(parameter.Value.GetRawText());
            }
        }
        var configuration = JsonSerializer.SerializeToElement(result);
        if (schemas.ValidateComponent("PolicyConfiguration", configuration).Count != 0)
        {
            throw new ApiProblemException(ProblemCodes.SchemaViolation, "template result violates policy schema");
        }
        PolicyRules.Validate(configuration);
        return configuration;
    }

    public static string Hash(JsonElement configuration) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(JsonNode.Parse(configuration.GetRawText()))!.ToJsonString())));

    private static JsonNode? Canonical(JsonNode? node) => node switch
    {
        JsonObject obj => new JsonObject(obj.OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => KeyValuePair.Create(p.Key, Canonical(p.Value)))),
        JsonArray array => new JsonArray(array.Select(Canonical).OrderBy(n => n?.ToJsonString(), StringComparer.Ordinal).ToArray()),
        _ => node?.DeepClone(),
    };
}
