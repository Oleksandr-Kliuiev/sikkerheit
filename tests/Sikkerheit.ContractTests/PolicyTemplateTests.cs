using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Contracts;
using Sikkerheit.ContractTests.Support;
using Sikkerheit.ContractTests.Invariants;
using Sikkerheit.Host.Organizations;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests;

[Enforcement("portal_api")]
public sealed class PolicyTemplateTests(PostgresFixture postgres)
{
    [Fact]
    public async Task Shared_library_is_admin_written_versioned_archivable_and_readable_by_other_staff()
    {
        await using var host = await ContractHost.StartAsync(postgres);
        var org = await host.OrganizationAsync();
        var body = await TemplateAsync(host, org);
        body["description"] = string.Empty;
        var technician = await host.SignInAsync("Technician");
        var reader = await host.SignInAsync("Reader");
        Assert.Equal(ProblemCodes.Forbidden, (await technician.PostAsync("/api/v1/policy-templates", body)).Code);
        Assert.Equal(ProblemCodes.Forbidden, (await reader.PostAsync("/api/v1/policy-templates", body)).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await host.Admin.PostAsync("/api/v1/policy-templates", body, csrf: false)).Status);
        var created = await host.Admin.PostAsync("/api/v1/policy-templates", body, "PolicyTemplate");
        var id = created.Body.GetProperty("id").GetGuid();
        var path = $"/api/v1/policy-templates/{id}";
        Assert.Equal("\"1\"", created.ETag);
        Assert.Equal(host.Admin.EntraUserId, created.Body.GetProperty("createdBy").GetGuid());
        Assert.Equal(id, (await reader.GetAsync(path, "PolicyTemplate")).Body.GetProperty("id").GetGuid());
        Assert.Single((await technician.GetAsync("/api/v1/policy-templates", "PolicyTemplatePage")).Body.GetProperty("items").EnumerateArray());
        body["archived"] = true;
        Assert.Equal(ProblemCodes.IfMatchRequired, (await host.Admin.PostAsync(path + "/revisions", body)).Code);
        var archived = await host.Admin.PostAsync(path + "/revisions", body, "PolicyTemplate", "\"1\"");
        Assert.Equal("\"2\"", archived.ETag);
        Assert.Equal(ProblemCodes.RevisionMismatch, (await host.Admin.PostAsync(path + "/revisions", body, ifMatch: "\"1\"")).Code);
        Assert.Empty((await reader.GetAsync("/api/v1/policy-templates", "PolicyTemplatePage")).Body.GetProperty("items").EnumerateArray());
        Assert.Single((await reader.GetAsync("/api/v1/policy-templates?includeArchived=true", "PolicyTemplatePage")).Body.GetProperty("items").EnumerateArray());
        var history = await reader.GetAsync(path + "/revisions?limit=1", "PolicyTemplatePage");
        Assert.Equal(2, history.Body.GetProperty("items")[0].GetProperty("revision").GetInt32());
        var cursor = Uri.EscapeDataString(history.Body.GetProperty("nextCursor").GetString()!);
        var older = await reader.GetAsync(path + "/revisions?limit=1&cursor=" + cursor, "PolicyTemplatePage");
        Assert.False(older.Body.GetProperty("items")[0].GetProperty("archived").GetBoolean());
        body["archived"] = false;
        Assert.Equal(HttpStatusCode.Created, (await host.Admin.PostAsync(path + "/revisions", body, "PolicyTemplate", "\"2\"")).Status);
    }

    [Fact]
    [Invariant("INV-202")]
    [Invariant("INV-205")]
    public async Task Preview_does_not_write_and_application_preserves_client_inputs_with_idempotent_atomic_receipt()
    {
        await using var host = await ContractHost.StartAsync(postgres);
        var org = await host.OrganizationAsync();
        var other = await host.OrganizationAsync("Other AS");
        var configuration = await host.PolicyAsync(org);
        var excluded = Guid.NewGuid().ToString();
        configuration["m365"]!["excludedUserIds"] = new JsonArray(excluded);
        configuration["m365"]!["collectionHourLocal"] = 19;
        configuration["checks"]!["WIN-010"]!["parameters"]!["expectedTenantId"] = Guid.NewGuid().ToString();
        configuration["checks"]!["WIN-003"]!["parameters"]!["approvedProviders"] = new JsonArray("Customer AV");
        configuration["checks"]!["WIN-008"]!["parameters"]!["allowedSids"] = new JsonArray("S-1-5-21-1-2-3-1001");
        await host.PolicyRevisionAsync(org, configuration, 1);
        var template = await CreateAsync(host, org);
        var preview = await PreviewAsync(host, template, org, other);
        Assert.Equal("ready", preview.GetProperty("items")[0].GetProperty("status").GetString());
        Assert.Equal(2, (await LatestAsync(host, org)).GetProperty("version").GetInt32());
        var item = preview.GetProperty("items")[0];
        var request = ApplyBody(template, item);
        var path = $"/api/v1/organizations/{org}/policy-template-applications";
        var wrongOrg = await host.Admin.PostAsync($"/api/v1/organizations/{other}/policy-template-applications", request, ifMatch: "\"2\"");
        Assert.Equal(ProblemCodes.InvalidCursor, wrongOrg.Code);
        var anotherAdmin = await host.SignInAsync("Admin");
        Assert.Equal(ProblemCodes.InvalidCursor, (await anotherAdmin.PostAsync(path, request, ifMatch: "\"2\"")).Code);
        Assert.Equal(ProblemCodes.IfMatchRequired, (await host.Admin.PostAsync(path, request)).Code);
        var concurrent = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => host.Admin.PostAsync(path, request, "PolicyTemplateApplication", "\"2\"")));
        Assert.All(concurrent, result => Assert.Equal(HttpStatusCode.OK, result.Status));
        Assert.Single(concurrent, result => !result.Body.GetProperty("replayed").GetBoolean());
        Assert.Single(concurrent, result => result.Body.GetProperty("replayed").GetBoolean());
        var latest = await LatestAsync(host, org);
        Assert.Equal(3, latest.GetProperty("version").GetInt32());
        var applied = latest.GetProperty("configuration");
        Assert.True(JsonNode.DeepEquals(configuration["m365"], JsonNode.Parse(applied.GetProperty("m365").GetRawText())));
        Assert.Equal(configuration["checks"]!["WIN-010"]!["parameters"]!.ToJsonString(),
            JsonNode.Parse(applied.GetProperty("checks").GetProperty("WIN-010").GetProperty("parameters").GetRawText())!.ToJsonString());
        Assert.False(applied.GetProperty("checks").GetProperty("M365-001").GetProperty("parameters").GetProperty("phoneMethodsAccepted").GetBoolean());
        Assert.Single(await host.AuditAsync(org, "policy.template_apply"));
        await using (var scope = await host.Scopes.OrganizationAsync(org, ContractHost.Ct))
            Assert.Equal(1, await scope.Db.Jobs.CountAsync(job => job.OrganizationId == org
                && job.Type == "recalculate_policy" && job.InputId == "policy:3", ContractHost.Ct));
        var noChanges = await PreviewAsync(host, template, org);
        Assert.Equal("unchanged", noChanges.GetProperty("items")[0].GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, noChanges.GetProperty("items")[0].GetProperty("previewToken").ValueKind);
        // The receipt is still available after expiration and subsequent policy revisions, without another write.
        host.Clock.Set(host.Clock.GetUtcNow().AddMinutes(31));
        var replayed = await host.Admin.PostAsync(path, request, "PolicyTemplateApplication", "\"2\"");
        Assert.True(replayed.Body.GetProperty("replayed").GetBoolean());
        Assert.Equal(3, (await LatestAsync(host, org)).GetProperty("version").GetInt32());
    }

    [Theory]
    [Invariant("INV-203")]
    [Invariant("INV-204")]
    [InlineData("policy")]
    [InlineData("template")]
    [InlineData("archive")]
    [InlineData("disabled")]
    [InlineData("expired")]
    [InlineData("tampered")]
    public async Task Changes_after_preview_or_tampering_never_create_a_revision(string change)
    {
        await using var host = await ContractHost.StartAsync(postgres);
        var org = await host.OrganizationAsync();
        var template = await CreateAsync(host, org);
        var preview = await PreviewAsync(host, template, org);
        var body = ApplyBody(template, preview.GetProperty("items")[0]);
        if (change == "policy") await host.PolicyRevisionAsync(org, await host.PolicyAsync(org), 1);
        if (change is "template" or "archive")
        {
            var next = await TemplateAsync(host, org); next["archived"] = change == "archive";
            await host.Admin.PostAsync($"/api/v1/policy-templates/{template.GetProperty("id").GetGuid()}/revisions", next, "PolicyTemplate", "\"1\"");
        }
        if (change == "disabled") await host.LifecycleAsync(org, "disable");
        if (change == "expired") host.Clock.Set(host.Clock.GetUtcNow().AddMinutes(31));
        if (change == "tampered") body["previewToken"] = body["previewToken"]!.GetValue<string>() + "x";
        var applied = await host.Admin.PostAsync($"/api/v1/organizations/{org}/policy-template-applications", body, ifMatch: "\"1\"");
        Assert.Equal(change switch
        {
            "policy" or "template" or "archive" => ProblemCodes.RevisionMismatch,
            "expired" => ProblemCodes.ValidationFailed,
            "tampered" => ProblemCodes.InvalidCursor,
            _ => ProblemCodes.LifecycleTransitionForbidden,
        }, applied.Code);
        Assert.Equal(change == "policy" ? 2 : 1, (await LatestAsync(host, org)).GetProperty("version").GetInt32());
        Assert.Empty(await host.AuditAsync(org, "policy.template_apply"));
    }

    [Fact]
    public async Task Nonportable_fields_and_unknown_checks_are_rejected_and_missing_clients_do_not_block_other_previews()
    {
        await using var host = await ContractHost.StartAsync(postgres);
        var org = await host.OrganizationAsync();
        var body = await TemplateAsync(host, org);
        body["content"]!["checks"]!["M365-002"]!["parameters"]!["privilegedRoleTemplateIds"] = new JsonArray(Guid.NewGuid().ToString());
        Assert.Equal(ProblemCodes.SchemaViolation, (await host.Admin.PostAsync("/api/v1/policy-templates", body)).Code);
        var template = await CreateAsync(host, org);
        var preview = await PreviewAsync(host, template, Guid.NewGuid(), org);
        Assert.Equal("unavailable", preview.GetProperty("items")[0].GetProperty("status").GetString());
        Assert.Equal("ready", preview.GetProperty("items")[1].GetProperty("status").GetString());
        var tooMany = Enumerable.Range(0, 51).Select(_ => Guid.NewGuid()).ToArray();
        var answer = await host.Admin.PostAsync($"/api/v1/policy-templates/{template.GetProperty("id").GetGuid()}/preview",
            new { organizationIds = tooMany }, ifMatch: "\"1\"");
        Assert.Equal(ProblemCodes.SchemaViolation, answer.Code);
        var duplicate = await host.Admin.PostAsync($"/api/v1/policy-templates/{template.GetProperty("id").GetGuid()}/preview",
            new { organizationIds = new[] { org, org } }, ifMatch: "\"1\"");
        Assert.Equal(ProblemCodes.SchemaViolation, duplicate.Code);
    }

    [Fact]
    public async Task Receipts_are_RLS_scoped_and_template_history_is_append_only_under_the_app_role()
    {
        await using var host = await ContractHost.StartAsync(postgres);
        var first = await host.OrganizationAsync();
        var second = await host.OrganizationAsync();
        var template = await CreateAsync(host, first);
        var preview = await PreviewAsync(host, template, first);
        await host.Admin.PostAsync($"/api/v1/organizations/{first}/policy-template-applications", ApplyBody(template, preview.GetProperty("items")[0]), "PolicyTemplateApplication", "\"1\"");
        await using (var scope = await host.Scopes.OrganizationAsync(second, ContractHost.Ct))
        {
            await using var command = new NpgsqlCommand("select count(*) from policy_template_application", scope.Connection, scope.Transaction);
            Assert.Equal(0L, await command.ExecuteScalarAsync(ContractHost.Ct));
        }
        await using (var scope = await host.Scopes.PlatformAsync(ContractHost.Ct))
        {
            await using var command = new NpgsqlCommand("delete from policy_template_revision", scope.Connection, scope.Transaction);
            var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(ContractHost.Ct));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
        }
    }

    [Fact]
    [Invariant("INV-206")]
    public async Task Archived_current_template_cannot_be_previewed()
    {
        await using var host = await ContractHost.StartAsync(postgres);
        var org = await host.OrganizationAsync();
        var template = await CreateAsync(host, org);
        var id = template.GetProperty("id").GetGuid();
        var body = await TemplateAsync(host, org); body["archived"] = true;
        await host.Admin.PostAsync($"/api/v1/policy-templates/{id}/revisions", body, "PolicyTemplate", "\"1\"");
        Assert.Equal(ProblemCodes.ValidationFailed, (await host.Admin.PostAsync($"/api/v1/policy-templates/{id}/preview",
            new { organizationIds = new[] { org } }, ifMatch: "\"2\"")).Code);
    }

    [Theory]
    [Invariant("INV-207")]
    [InlineData("windows")]
    [InlineData("all")]
    public async Task Portable_scope_preserves_customer_exceptions_and_provider_inputs(string scopeName)
    {
        await using var host = await ContractHost.StartAsync(postgres);
        var org = await host.OrganizationAsync();
        var policy = await host.PolicyAsync(org);
        policy["checks"]!["WIN-003"]!["parameters"]!["approvedProviders"] = new JsonArray("Client AV");
        policy["checks"]!["WIN-003"]!["parameters"]!["defenderApproved"] = false;
        policy["checks"]!["WIN-008"]!["parameters"]!["allowedSids"] = new JsonArray("S-1-5-21-1-2-3-1001");
        policy["checks"]!["WIN-008"]!["parameters"]!["allowedDomainRids"] = new JsonArray(513);
        policy["checks"]!["WIN-002"]!["notApplicableEditionIds"] = new JsonArray("CoreN");
        await host.PolicyRevisionAsync(org, policy, 1);
        var body = await TemplateAsync(host, org, scopeName);
        body["content"]!["checks"]!["WIN-001"]!["parameters"]!["warnFreePercent"] = 22;
        var template = (await host.Admin.PostAsync("/api/v1/policy-templates", body, "PolicyTemplate")).Body;
        var preview = await PreviewAsync(host, template, org);
        var applied = await host.Admin.PostAsync($"/api/v1/organizations/{org}/policy-template-applications",
            ApplyBody(template, preview.GetProperty("items")[0]), "PolicyTemplateApplication", "\"2\"");
        Assert.Equal(HttpStatusCode.OK, applied.Status);
        var after = (await LatestAsync(host, org)).GetProperty("configuration");
        Assert.Equal(22, after.GetProperty("checks").GetProperty("WIN-001").GetProperty("parameters").GetProperty("warnFreePercent").GetInt32());
        foreach (var check in new[] { "WIN-003", "WIN-008", "WIN-010" })
            Assert.True(JsonNode.DeepEquals(policy["checks"]![check]!["parameters"], JsonNode.Parse(after.GetProperty("checks").GetProperty(check).GetProperty("parameters").GetRawText())));
        Assert.True(JsonNode.DeepEquals(policy["checks"]!["WIN-002"]!["notApplicableEditionIds"], JsonNode.Parse(after.GetProperty("checks").GetProperty("WIN-002").GetProperty("notApplicableEditionIds").GetRawText())));
    }

    [Fact]
    public async Task Reordering_set_parameters_is_unchanged_and_never_issues_an_apply_token()
    {
        await using var host = await ContractHost.StartAsync(postgres);
        var org = await host.OrganizationAsync();
        var body = await TemplateAsync(host, org, "windows");
        body["content"]!["checks"]!["WIN-001"]!["parameters"]!["warnFreePercent"] = 10;
        body["content"]!["checks"]!["WIN-005"]!["parameters"]!["requiredProfiles"] = new JsonArray("public", "private", "domain");
        var template = (await host.Admin.PostAsync("/api/v1/policy-templates", body, "PolicyTemplate")).Body;
        var row = (await PreviewAsync(host, template, org)).GetProperty("items")[0];
        Assert.Equal("unchanged", row.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, row.GetProperty("previewToken").ValueKind);
    }

    [Fact]
    public async Task A_receipt_failure_rolls_back_policy_counter_audit_and_job_and_the_same_preview_can_be_retried()
    {
        await using var host = await ContractHost.StartAsync(postgres);
        var org = await host.OrganizationAsync();
        var template = await CreateAsync(host, org);
        var preview = await PreviewAsync(host, template, org);
        var body = ApplyBody(template, preview.GetProperty("items")[0]);
        var ownerString = new NpgsqlConnectionStringBuilder(postgres.OwnerConnectionString)
        { Database = new NpgsqlConnectionStringBuilder(host.Factory.ConnectionString).Database }.ConnectionString;
        await using var owner = new NpgsqlConnection(ownerString);
        await owner.OpenAsync(ContractHost.Ct);
        await using (var fail = new NpgsqlCommand("""
            create function fail_template_receipt() returns trigger language plpgsql as $$
            begin raise exception 'synthetic receipt write failure'; end; $$;
            create trigger fail_template_receipt before insert on policy_template_application
            for each row execute function fail_template_receipt()
            """, owner)) await fail.ExecuteNonQueryAsync(ContractHost.Ct);
        var path = $"/api/v1/organizations/{org}/policy-template-applications";
        var failure = await host.Admin.PostAsync(path, body, ifMatch: "\"1\"");
        Assert.True((int)failure.Status >= 500);
        Assert.Equal(1, (await LatestAsync(host, org)).GetProperty("version").GetInt32());
        Assert.Empty(await host.AuditAsync(org, "policy.template_apply"));
        Assert.Empty(await host.AuditAsync(org, "policy.revision_create"));
        await using (var scope = await host.Scopes.OrganizationAsync(org, ContractHost.Ct))
        {
            Assert.Equal(2, (await scope.Db.Organizations.SingleAsync(o => o.Id == org, ContractHost.Ct)).NextPolicyVersion);
            Assert.False(await scope.Db.Jobs.AnyAsync(j => j.OrganizationId == org && j.Type == "recalculate_policy", ContractHost.Ct));
        }
        await using (var repair = new NpgsqlCommand("drop trigger fail_template_receipt on policy_template_application; drop function fail_template_receipt()", owner))
            await repair.ExecuteNonQueryAsync(ContractHost.Ct);
        var success = await host.Admin.PostAsync(path, body, "PolicyTemplateApplication", "\"1\"");
        Assert.Equal(2, success.Body.GetProperty("policyVersion").GetInt32());
        Assert.False(success.Body.GetProperty("replayed").GetBoolean());
    }

    private static async Task<JsonElement> LatestAsync(ContractHost host, Guid org) =>
        (await host.Admin.GetAsync($"/api/v1/organizations/{org}/policy-revisions?limit=1", "PolicyRevisionPage")).Body.GetProperty("items")[0];

    private static async Task<JsonObject> TemplateAsync(ContractHost host, Guid org, string scope = "m365")
    {
        var policy = await host.PolicyAsync(org);
        var schema = new ContractSchemas().Api.GetProperty("components").GetProperty("schemas").GetProperty("PolicyTemplateContent")
            .GetProperty("oneOf").EnumerateArray().Single(s => s.GetProperty("properties").GetProperty("scope").GetProperty("const").GetString() == scope).GetProperty("properties");
        var checks = new JsonObject();
        foreach (var property in schema.GetProperty("checks").GetProperty("properties").EnumerateObject())
        {
            var check = policy["checks"]![property.Name]!;
            var parameters = new JsonObject();
            foreach (var parameter in property.Value.GetProperty("properties").GetProperty("parameters").GetProperty("properties").EnumerateObject())
                parameters[parameter.Name] = check["parameters"]![parameter.Name]!.DeepClone();
            checks[property.Name] = new JsonObject { ["assessmentMode"] = check["assessmentMode"]!.DeepClone(),
                ["freshnessWindowHours"] = check["freshnessWindowHours"]!.DeepClone(), ["parameters"] = parameters };
        }
        if (scope != "windows") checks["M365-001"]!["parameters"]!["phoneMethodsAccepted"] = false;
        else checks["WIN-001"]!["parameters"]!["warnFreePercent"] = 20;
        var ids = new JsonArray(checks.Where(pair => !pair.Key.StartsWith("SYS-", StringComparison.Ordinal)).Select(pair => (JsonNode?)JsonValue.Create(pair.Key)).ToArray());
        return new JsonObject { ["name"] = "Portable MFA", ["description"] = "Test template",
            ["content"] = new JsonObject { ["scope"] = scope, ["activeCheckIds"] = ids, ["checks"] = checks } };
    }

    private static async Task<JsonElement> CreateAsync(ContractHost host, Guid org) =>
        (await host.Admin.PostAsync("/api/v1/policy-templates", await TemplateAsync(host, org), "PolicyTemplate")).Body;

    private static async Task<JsonElement> PreviewAsync(ContractHost host, JsonElement template, params Guid[] orgs) =>
        (await host.Admin.PostAsync($"/api/v1/policy-templates/{template.GetProperty("id").GetGuid()}/preview", new { organizationIds = orgs },
            "PolicyTemplatePreview", "\"1\"")).Body;

    private static JsonObject ApplyBody(JsonElement template, JsonElement item) => new()
    {
        ["templateId"] = template.GetProperty("id").GetGuid().ToString(), ["templateRevision"] = template.GetProperty("revision").GetInt32(),
        ["previewToken"] = item.GetProperty("previewToken").GetString(),
    };
}
