using System.Text.Json;
using Sikkerheit.Contracts;
using Sikkerheit.ContractTests.Invariants;

namespace Sikkerheit.ContractTests;

/// <summary>Records enforced by the contract schemas themselves (specs/openapi.json, embedded in Sikkerheit.Contracts).</summary>
[Enforcement("schema")]
public sealed class SchemaInvariantTests
{
    private static readonly ContractSchemas Schemas = new();

    [Theory]
    [Invariant("INV-061")]
    [InlineData("risk_accepted")]
    [InlineData("suppressed")]
    public void Inv061_finding_patch_cannot_set_a_risk_decision_state(string state)
    {
        using var body = JsonDocument.Parse($$"""{"workflowState":"{{state}}"}""");
        Assert.NotEmpty(Schemas.ValidateComponent("FindingPatch", body.RootElement));
        using var allowed = JsonDocument.Parse("""{"workflowState":"in_progress"}""");
        Assert.Empty(Schemas.ValidateComponent("FindingPatch", allowed.RootElement));
        // The portal answers a body outside the schema with 422 schema_violation.
        Assert.Equal(422, Catalog.StatusOf(ProblemCodes.SchemaViolation));
    }
}
