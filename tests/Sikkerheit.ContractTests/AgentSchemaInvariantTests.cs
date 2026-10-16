using System.Text.Json;
using System.Text.Json.Nodes;
using Sikkerheit.Contracts;
using Sikkerheit.ContractTests.Invariants;

namespace Sikkerheit.ContractTests;

/// <summary>Records enforced by the contract schemas of the batch of the agent (specs/openapi.json, scan-batch.schema.json).</summary>
[Enforcement("schema")]
public sealed class AgentSchemaInvariantTests
{
    private static readonly ContractSchemas Schemas = new();

    private static JsonObject Example() => JsonNode.Parse(File.ReadAllText(
        Path.Combine(InvariantRegistry.Root, "development-package", "examples", "scan-batch.json")))!.AsObject();

    private static int Violations(JsonObject batch) =>
        Schemas.ValidateComponent("ScanBatch", JsonDocument.Parse(batch.ToJsonString()).RootElement).Count;

    [Fact]
    [Invariant("INV-121")]
    public void Inv121_a_field_outside_the_schema_an_organization_id_or_foreign_evidence_reject_the_whole_batch()
    {
        Assert.Equal(0, Violations(Example()));

        var withOrganization = Example();
        withOrganization["organizationId"] = Guid.NewGuid().ToString();
        Assert.NotEqual(0, Violations(withOrganization));

        var extra = Example();
        extra["observations"]![0]!["note"] = "x";
        Assert.NotEqual(0, Violations(extra));

        // WIN-001 carrying the evidence of WIN-002.
        var foreign = Example();
        foreign["observations"]![0]!["evidence"] = foreign["observations"]![1]!["evidence"]!.DeepClone();
        Assert.NotEqual(0, Violations(foreign));

        // The service answers such a batch with 422 schema_violation.
        Assert.Equal(422, Catalog.StatusOf(ProblemCodes.SchemaViolation));
    }
}
