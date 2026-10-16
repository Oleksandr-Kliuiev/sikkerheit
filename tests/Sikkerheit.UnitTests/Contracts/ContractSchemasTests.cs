using System.Text.Json;
using Sikkerheit.Contracts;

namespace Sikkerheit.UnitTests.Contracts;

public sealed class ContractSchemasTests
{
    private static readonly ContractSchemas Schemas = new();

    private static JsonElement Json(string text) => JsonDocument.Parse(text).RootElement.Clone();

    [Fact]
    public void Organization_create_accepts_a_valid_body()
    {
        var body = Json("""{"name":"Fjord AS","timezone":"Europe/Oslo","reportLanguage":"nn"}""");
        Assert.Empty(Schemas.ValidateComponent("OrganizationCreate", body));
    }

    [Theory]
    [InlineData("""{"name":"Fjord AS","timezone":"Europe/Oslo","reportLanguage":"nn","organizationId":"x"}""")]
    [InlineData("""{"name":"Fjord AS","timezone":"Europe/Oslo","reportLanguage":"sv"}""")]
    [InlineData("""{"name":"Fjord AS","reportLanguage":"nb"}""")]
    [InlineData("""{"name":"<script>","timezone":"Europe/Oslo","reportLanguage":"nb"}""")]
    public void Organization_create_rejects_bodies_outside_the_schema(string text)
    {
        Assert.NotEmpty(Schemas.ValidateComponent("OrganizationCreate", Json(text)));
    }

    [Fact]
    public void Synthetic_m365_collection_matches_its_standalone_schema()
    {
        var run = JsonDocument.Parse(File.ReadAllText(RepoPaths.Package("examples", "m365-collection.json"))).RootElement;
        Assert.Empty(Schemas.ValidateStandalone("graph-collection.schema.json", run));
    }

    [Fact]
    public void Scan_batch_example_matches_the_openapi_component()
    {
        var batch = JsonDocument.Parse(File.ReadAllText(RepoPaths.Package("examples", "scan-batch.json"))).RootElement;
        Assert.Empty(Schemas.ValidateComponent("ScanBatch", batch));
    }

    [Fact]
    public void Catalog_matches_the_embedded_check_catalog()
    {
        var ids = Schemas.CheckCatalog.GetProperty("checks").EnumerateArray().Select(c => c.GetProperty("checkId").GetString());
        Assert.Equal(Catalog.Checks.Select(c => c.CheckId), ids);
        Assert.Equal(Catalog.Version, Schemas.CheckCatalog.GetProperty("catalogVersion").GetString());
    }
}
