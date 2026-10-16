using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using Json.Schema;

namespace Sikkerheit.Contracts;

/// <summary>A violation of a contract schema: JSON pointer of the instance and the validator message.</summary>
public sealed record ContractViolation(string InstanceLocation, string Message);

/// <summary>
/// Validates JSON against the embedded contract: OpenAPI component schemas (by name) and the standalone
/// observation and collection schemas. The contract files are linked from development-package/specs.
/// </summary>
public sealed class ContractSchemas
{
    private static readonly Uri ApiUri = new("urn:sikkerheit:openapi");
    private static readonly string[] Standalone =
        ["observation.schema.json", "scan-batch.schema.json", "graph-observation.schema.json", "graph-collection.schema.json"];

    private readonly BuildOptions _build;
    private readonly ConcurrentDictionary<string, JsonSchema> _cache = new(StringComparer.Ordinal);
    private readonly EvaluationOptions _evaluation = new() { OutputFormat = OutputFormat.List, RequireFormatValidation = true };
    private readonly Dictionary<string, Uri> _standaloneIds = new(StringComparer.Ordinal);

    public ContractSchemas()
    {
        var registry = new SchemaRegistry();
        Api = ReadJson("openapi.json");
        registry.Register(ApiUri, new JsonElementBaseDocument(Api, ApiUri));
        foreach (var name in Standalone)
        {
            var schema = ReadJson(name);
            var id = new Uri(schema.GetProperty("$id").GetString()!);
            registry.Register(id, new JsonElementBaseDocument(schema, id));
            _standaloneIds[name] = id;
        }
        _build = new BuildOptions { SchemaRegistry = registry };
        CheckCatalog = ReadJson("check-catalog.json");
    }

    /// <summary>The embedded OpenAPI document.</summary>
    public JsonElement Api { get; }

    /// <summary>The embedded check catalog (specs/check-catalog.json).</summary>
    public JsonElement CheckCatalog { get; }

    public bool HasComponent(string name) =>
        Api.GetProperty("components").GetProperty("schemas").TryGetProperty(name, out _);

    /// <summary>Validates an instance against an OpenAPI component schema.</summary>
    public IReadOnlyList<ContractViolation> ValidateComponent(string component, JsonElement instance) =>
        Evaluate(_cache.GetOrAdd("c:" + component, _ => Reference($"{ApiUri}#/components/schemas/{component}")), instance);

    /// <summary>Validates an instance against a standalone schema such as graph-collection.schema.json.</summary>
    public IReadOnlyList<ContractViolation> ValidateStandalone(string file, JsonElement instance) =>
        Evaluate(_cache.GetOrAdd("s:" + file, _ => Reference(_standaloneIds[file].ToString())), instance);

    /// <summary>
    /// Validates the headers of a response against the operation in the OpenAPI document: every declared header must be
    /// present and match its schema, and the media type of Content-Type must be one of the declared contents.
    /// </summary>
    public IReadOnlyList<ContractViolation> ValidateResponseHeaders(string operationId, int status,
        IReadOnlyDictionary<string, string> headers)
    {
        var violations = new List<ContractViolation>();
        var operation = Operation(operationId);
        if (!operation.GetProperty("responses").TryGetProperty(status.ToString(CultureInfo.InvariantCulture), out var response))
        {
            violations.Add(new ContractViolation("status", $"{operationId} declares no response {status}"));
            return violations;
        }
        if (response.TryGetProperty("content", out var content))
        {
            var mediaType = headers.TryGetValue("Content-Type", out var type) ? type.Split(';')[0].Trim() : "";
            if (!content.TryGetProperty(mediaType, out _))
            {
                violations.Add(new ContractViolation("Content-Type", $"media type '{mediaType}' is not declared"));
            }
        }
        if (!response.TryGetProperty("headers", out var declared))
        {
            return violations;
        }
        foreach (var header in declared.EnumerateObject())
        {
            if (!headers.TryGetValue(header.Name, out var value))
            {
                violations.Add(new ContractViolation(header.Name, "header is missing"));
                continue;
            }
            var schema = _cache.GetOrAdd($"h:{operationId}:{status}:{header.Name}", _ => JsonSchema.FromText(
                header.Value.GetProperty("schema").GetRawText(), _build, new Uri($"urn:sikkerheit:header:{Guid.NewGuid():N}")));
            using var instance = JsonDocument.Parse(JsonSerializer.Serialize(value));
            violations.AddRange(Evaluate(schema, instance.RootElement).Select(v => v with { InstanceLocation = header.Name }));
        }
        return violations;
    }

    private JsonElement Operation(string operationId)
    {
        foreach (var path in Api.GetProperty("paths").EnumerateObject())
        {
            foreach (var method in path.Value.EnumerateObject())
            {
                if (method.Value.ValueKind == JsonValueKind.Object && method.Value.TryGetProperty("operationId", out var id)
                    && id.GetString() == operationId)
                {
                    return method.Value;
                }
            }
        }
        throw new ArgumentException("Unknown operationId " + operationId, nameof(operationId));
    }

    private JsonSchema Reference(string target)
    {
        var text = JsonSerializer.Serialize(new Dictionary<string, string> { ["$ref"] = target });
        return JsonSchema.FromText(text, _build, new Uri($"urn:sikkerheit:ref:{Guid.NewGuid():N}"));
    }

    private IReadOnlyList<ContractViolation> Evaluate(JsonSchema schema, JsonElement instance)
    {
        var results = schema.Evaluate(instance, _evaluation);
        if (results.IsValid)
        {
            return [];
        }
        var violations = new List<ContractViolation>();
        foreach (var detail in results.Details ?? [])
        {
            if (detail.Errors is null)
            {
                continue;
            }
            foreach (var error in detail.Errors)
            {
                violations.Add(new ContractViolation(detail.InstanceLocation.ToString(), $"{error.Key}: {error.Value}"));
            }
        }
        if (violations.Count == 0)
        {
            violations.Add(new ContractViolation("", "instance does not match the schema"));
        }
        return violations;
    }

    private static JsonElement ReadJson(string name)
    {
        var assembly = typeof(ContractSchemas).Assembly;
        using var stream = assembly.GetManifestResourceStream($"Sikkerheit.Contracts.{name}")
            ?? throw new InvalidOperationException($"Embedded contract file {name} is missing");
        using var document = JsonDocument.Parse(stream);
        return document.RootElement.Clone();
    }
}
