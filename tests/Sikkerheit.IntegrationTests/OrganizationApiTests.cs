using System.Net;
using System.Text.Json;
using Sikkerheit.Contracts;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.IntegrationTests;

/// <summary>FR-01, FR-02, FR-03: organizations, lifecycle, policy and audit over HTTP (AT-01, AT-02, AT-06, AT-09).</summary>
public sealed class OrganizationApiTests(PostgresFixture postgres) : IAsyncLifetime
{
    private ApiFactory _factory = null!;
    private StaffClient _admin = null!;

    public async ValueTask InitializeAsync()
    {
        _factory = await ApiFactory.CreateAsync(postgres);
        _admin = await StaffClient.SignInAsync(_factory, "Admin");
    }

    public async ValueTask DisposeAsync() => await _factory.DisposeAsync();

    private async Task<string> CreateOrganizationAsync(string name = "Fjordkraft Rør AS")
    {
        var created = await _admin.PostAsync("/api/v1/organizations",
            new { name, timezone = "Europe/Oslo", reportLanguage = "nn" }, "Organization");
        Assert.Equal(HttpStatusCode.Created, created.Status);
        return created.Body.GetProperty("id").GetString()!;
    }

    private Task<StaffClient.Answer> Lifecycle(string org, string action, Guid? key = null, bool? exportWaived = null,
        StaffClient? client = null)
    {
        object body = exportWaived is null
            ? new { action, reason = "Kunde avslutter avtalen", idempotencyKey = key ?? Guid.NewGuid() }
            : new { action, reason = "Kunde avslutter avtalen", idempotencyKey = key ?? Guid.NewGuid(), exportWaived };
        return (client ?? _admin).PostAsync($"/api/v1/organizations/{org}/lifecycle", body, "Organization");
    }

    [Fact]
    public async Task Request_without_session_is_401_session_required()
    {
        using var anonymous = StaffClient.Anonymous(_factory);
        var answer = await StaffClient.Answer.ReadAsync(await anonymous.GetAsync("/api/v1/organizations", TestContext.Current.CancellationToken), null);
        Assert.Equal(HttpStatusCode.Unauthorized, answer.Status);
        Assert.Equal(ProblemCodes.SessionRequired, answer.Code);
    }

    [Fact]
    public async Task Admin_creates_an_organization_with_policy_v1_and_an_unconnected_tenant()
    {
        var org = await CreateOrganizationAsync();
        var fetched = await _admin.GetAsync($"/api/v1/organizations/{org}", "Organization");
        Assert.Equal("active", fetched.Body.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, fetched.Body.GetProperty("deletionDueAt").ValueKind);

        var policies = await _admin.GetAsync($"/api/v1/organizations/{org}/policy-revisions", "PolicyRevisionPage");
        var revision = Assert.Single(policies.Body.GetProperty("items").EnumerateArray());
        Assert.Equal(1, revision.GetProperty("version").GetInt32());
        var activeChecks = revision.GetProperty("configuration").GetProperty("activeCheckIds").GetArrayLength();
        Assert.Equal(Catalog.Checks.Count(c => c.Source != "server"), activeChecks);

        var list = await _admin.GetAsync("/api/v1/organizations?limit=100", "OrganizationOverviewPage");
        var overview = list.Body.GetProperty("items").EnumerateArray()
            .Single(i => i.GetProperty("organization").GetProperty("id").GetString() == org);
        Assert.Equal("not_connected", overview.GetProperty("m365Status").GetString());
    }

    [Fact]
    public async Task Reader_and_technician_cannot_create_organizations()
    {
        foreach (var role in new[] { "Reader", "Technician" })
        {
            var client = await StaffClient.SignInAsync(_factory, role);
            var answer = await client.PostAsync("/api/v1/organizations",
                new { name = "Nope AS", timezone = "Europe/Oslo", reportLanguage = "nb" });
            Assert.Equal(HttpStatusCode.Forbidden, answer.Status);
            Assert.Equal(ProblemCodes.Forbidden, answer.Code);
        }
    }

    [Fact]
    public async Task Mutation_without_or_with_a_foreign_csrf_token_is_refused()
    {
        var other = await StaffClient.SignInAsync(_factory, "Admin");
        var body = JsonSerializer.Serialize(new { name = "Csrf AS", timezone = "Europe/Oslo", reportLanguage = "nb" });
        var missing = await _admin.SendAsync(HttpMethod.Post, "/api/v1/organizations", body, null, csrf: false);
        var foreign = await _admin.SendAsync(HttpMethod.Post, "/api/v1/organizations", body, null, csrfOverride: other.Csrf);
        Assert.Equal(ProblemCodes.CsrfFailed, missing.Code);
        Assert.Equal(ProblemCodes.CsrfFailed, foreign.Code);
    }

    [Theory]
    [InlineData("""{"name":"X","timezone":"Mars/Olympus","reportLanguage":"nb"}""", 422, "validation_failed")]
    [InlineData("""{"name":"X","timezone":"Europe/Oslo","reportLanguage":"nb","organizationId":"1"}""", 422, "schema_violation")]
    [InlineData("""{"name":"X","timezone":""", 400, "invalid_json")]
    public async Task Create_rejects_invalid_bodies(string json, int status, string code)
    {
        var answer = await _admin.SendAsync(HttpMethod.Post, "/api/v1/organizations", json, null);
        Assert.Equal(status, (int)answer.Status);
        Assert.Equal(code, answer.Code);
    }

    [Fact]
    public async Task Create_rejects_other_media_types_and_oversized_bodies()
    {
        var text = await _admin.SendAsync(HttpMethod.Post, "/api/v1/organizations", "{}", null, contentType: "text/plain");
        Assert.Equal(ProblemCodes.UnsupportedMediaType, text.Code);
        var huge = JsonSerializer.Serialize(new { name = new string('a', 70000), timezone = "Europe/Oslo", reportLanguage = "nb" });
        var tooLarge = await _admin.SendAsync(HttpMethod.Post, "/api/v1/organizations", huge, null);
        Assert.Equal(ProblemCodes.PayloadTooLarge, tooLarge.Code);
    }

    [Fact]
    public async Task Unknown_organization_is_404()
    {
        var answer = await _admin.GetAsync($"/api/v1/organizations/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.NotFound, answer.Status);
        Assert.Equal(ProblemCodes.NotFound, answer.Code);
    }

    [Fact]
    public async Task Lifecycle_follows_the_transition_table_and_writes_the_security_log()
    {
        var org = await CreateOrganizationAsync();
        var disabled = await Lifecycle(org, "disable");
        Assert.Equal("disabled", disabled.Body.GetProperty("status").GetString());

        var update = await _admin.PatchAsync($"/api/v1/organizations/{org}", new { name = "Renamed AS" });
        Assert.Equal(ProblemCodes.LifecycleTransitionForbidden, update.Code);

        var withoutExport = await Lifecycle(org, "schedule_deletion");
        Assert.Equal(ProblemCodes.LifecycleTransitionForbidden, withoutExport.Code);

        var scheduled = await Lifecycle(org, "schedule_deletion", exportWaived: true);
        Assert.Equal("deletion_scheduled", scheduled.Body.GetProperty("status").GetString());
        var due = scheduled.Body.GetProperty("deletionDueAt").GetDateTimeOffset();
        Assert.InRange(due - DateTimeOffset.UtcNow, TimeSpan.FromDays(29.9), TimeSpan.FromDays(30.1));

        var cancelled = await Lifecycle(org, "cancel_deletion");
        Assert.Equal("disabled", cancelled.Body.GetProperty("status").GetString());
        var enabled = await Lifecycle(org, "enable");
        Assert.Equal("active", enabled.Body.GetProperty("status").GetString());

        var forbidden = await Lifecycle(org, "enable");
        Assert.Equal(ProblemCodes.LifecycleTransitionForbidden, forbidden.Code);

        var logged = Directory.GetFiles(_factory.SecurityLogDirectory)
            .Select(f => JsonDocument.Parse(File.ReadAllText(f)).RootElement)
            .Where(r => r.GetProperty("organizationId").GetString() == org)
            .Select(r => r.GetProperty("action").GetString())
            .Order()
            .ToList();
        Assert.Equal(["organization.cancel_deletion", "organization.disable", "organization.schedule_deletion"], logged);
    }

    [Fact]
    public async Task Lifecycle_repeat_with_the_same_key_returns_the_first_result()
    {
        var org = await CreateOrganizationAsync();
        var key = Guid.NewGuid();
        var first = await Lifecycle(org, "disable", key);
        var repeat = await Lifecycle(org, "disable", key);
        Assert.Equal(HttpStatusCode.OK, repeat.Status);
        Assert.Equal(first.Body.GetRawText(), repeat.Body.GetRawText());

        var conflict = await _admin.PostAsync($"/api/v1/organizations/{org}/lifecycle",
            new { action = "disable", reason = "Annen grunn", idempotencyKey = key }, "Organization");
        Assert.Equal(ProblemCodes.IdempotencyConflict, conflict.Code);
    }

    [Fact]
    public async Task Restrictive_transition_is_refused_when_the_security_log_is_unavailable()
    {
        var blocked = Path.Combine(Path.GetTempPath(), "sikkerheit-tests", "blocked-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.GetDirectoryName(blocked)!);
        await File.WriteAllTextAsync(blocked, "not a directory", TestContext.Current.CancellationToken);
        await using var factory = await ApiFactory.CreateAsync(postgres, blocked);
        var admin = await StaffClient.SignInAsync(factory, "Admin");
        var created = await admin.PostAsync("/api/v1/organizations",
            new { name = "Logless AS", timezone = "Europe/Oslo", reportLanguage = "nb" }, "Organization");
        var org = created.Body.GetProperty("id").GetString();
        var answer = await Lifecycle(org!, "disable", client: admin);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, answer.Status);
        Assert.Equal(ProblemCodes.TemporarilyUnavailable, answer.Code);
        var after = await admin.GetAsync($"/api/v1/organizations/{org}", "Organization");
        Assert.Equal("active", after.Body.GetProperty("status").GetString());
    }

    [Fact]
    public async Task Policy_revision_needs_if_match_and_enforces_the_rules_beyond_the_schema()
    {
        var org = await CreateOrganizationAsync();
        var current = (await _admin.GetAsync($"/api/v1/organizations/{org}/policy-revisions", "PolicyRevisionPage"))
            .Body.GetProperty("items")[0].GetProperty("configuration");
        var path = $"/api/v1/organizations/{org}/policy-revisions";

        var missing = await _admin.PostAsync(path, new { configuration = current });
        Assert.Equal(ProblemCodes.IfMatchRequired, missing.Code);
        var stale = await _admin.PostAsync(path, new { configuration = current }, ifMatch: "\"7\"");
        Assert.Equal(ProblemCodes.RevisionMismatch, stale.Code);

        var noWin003 = Mutate(current, c => c["activeCheckIds"] = new System.Text.Json.Nodes.JsonArray(
            c["activeCheckIds"]!.AsArray().Where(x => x!.GetValue<string>() != "WIN-003").Select(x => x!.DeepClone()).ToArray()));
        Assert.Equal(ProblemCodes.PolicyInputsMissing, (await _admin.PostAsync(path, new { configuration = noWin003 }, ifMatch: "\"1\"")).Code);

        var thresholds = Mutate(current, c => c["checks"]!["WIN-004"]!["parameters"]!["warnDays"] = 10);
        Assert.Equal(ProblemCodes.ValidationFailed, (await _admin.PostAsync(path, new { configuration = thresholds }, ifMatch: "\"1\"")).Code);

        var outOfRange = Mutate(current, c => c["checks"]!["WIN-006"]!["parameters"]!["maxSearchAgeDays"] = 61);
        Assert.Equal(ProblemCodes.SchemaViolation, (await _admin.PostAsync(path, new { configuration = outOfRange }, ifMatch: "\"1\"")).Code);

        var created = await _admin.PostAsync(path, new { configuration = current }, "PolicyRevision", ifMatch: "\"1\"");
        Assert.Equal(HttpStatusCode.Created, created.Status);
        Assert.Equal("\"2\"", created.ETag);
        Assert.Equal(2, created.Body.GetProperty("version").GetInt32());
    }

    [Fact]
    public async Task Audit_journal_lists_changes_with_closed_details_and_audits_its_own_reads()
    {
        var org = await CreateOrganizationAsync();
        await Lifecycle(org, "disable");
        var first = await _admin.GetAsync($"/api/v1/organizations/{org}/audit-events", "AuditEventPage");
        var actions = first.Body.GetProperty("items").EnumerateArray().Select(e => e.GetProperty("action").GetString()).ToList();
        Assert.Contains("organization.create", actions);
        Assert.Contains("organization.lifecycle_change", actions);
        var lifecycle = first.Body.GetProperty("items").EnumerateArray()
            .Single(e => e.GetProperty("action").GetString() == "organization.lifecycle_change");
        Assert.Equal("disable", lifecycle.GetProperty("details").GetProperty("lifecycleAction").GetString());

        var second = await _admin.GetAsync($"/api/v1/organizations/{org}/audit-events", "AuditEventPage");
        Assert.Contains(second.Body.GetProperty("items").EnumerateArray(), e => e.GetProperty("action").GetString() == "audit_events.read");

        var technician = await StaffClient.SignInAsync(_factory, "Technician");
        Assert.Equal(ProblemCodes.Forbidden, (await technician.GetAsync($"/api/v1/organizations/{org}/audit-events")).Code);
    }

    [Fact]
    public async Task Cursor_pages_and_foreign_cursors_are_refused()
    {
        for (var i = 0; i < 3; i++)
        {
            await CreateOrganizationAsync($"Paging {i} AS");
        }
        var page = await _admin.GetAsync("/api/v1/organizations?limit=1", "OrganizationOverviewPage");
        var cursor = page.Body.GetProperty("nextCursor").GetString()!;
        var next = await _admin.GetAsync($"/api/v1/organizations?limit=1&cursor={Uri.EscapeDataString(cursor)}", "OrganizationOverviewPage");
        Assert.NotEqual(page.Body.GetProperty("items")[0].GetRawText(), next.Body.GetProperty("items")[0].GetRawText());

        var org = await CreateOrganizationAsync();
        var foreign = await _admin.GetAsync($"/api/v1/organizations/{org}/policy-revisions?cursor={Uri.EscapeDataString(cursor)}");
        Assert.Equal(ProblemCodes.InvalidCursor, foreign.Code);
        var tampered = await _admin.GetAsync($"/api/v1/organizations?cursor={Uri.EscapeDataString(cursor[..^2] + "AA")}");
        Assert.Equal(ProblemCodes.InvalidCursor, tampered.Code);
    }

    [Fact]
    public async Task Current_staff_returns_roles_and_the_csrf_token()
    {
        var me = await _admin.GetAsync("/api/v1/me", "CurrentStaff");
        Assert.Equal(_admin.EntraUserId.ToString(), me.Body.GetProperty("entraUserId").GetString());
        Assert.Equal(_admin.Csrf, me.Body.GetProperty("csrfToken").GetString());
        var staff = await _admin.GetAsync("/api/v1/staff?limit=100", "StaffUserPage");
        Assert.Contains(staff.Body.GetProperty("items").EnumerateArray(),
            s => s.GetProperty("entraUserId").GetString() == _admin.EntraUserId.ToString() && s.GetProperty("active").GetBoolean());
    }

    private static JsonElement Mutate(JsonElement source, Action<System.Text.Json.Nodes.JsonObject> change)
    {
        var node = System.Text.Json.Nodes.JsonNode.Parse(source.GetRawText())!.AsObject();
        change(node);
        return JsonDocument.Parse(node.ToJsonString()).RootElement.Clone();
    }
}
