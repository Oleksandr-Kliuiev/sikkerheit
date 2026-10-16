using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Contracts;
using Sikkerheit.ContractTests.Invariants;
using Sikkerheit.ContractTests.Support;
using Sikkerheit.Host.Access;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests;

/// <summary>Records enforced by the portal API: each test sends the negative example over HTTP and expects the record's error.</summary>
[Enforcement("portal_api")]
public sealed class PortalApiInvariantTests(PostgresFixture postgres) : IAsyncLifetime
{
    private static readonly Guid CompanyTenant = Guid.Parse("c0c0c0c0-0000-4000-8000-000000000001");
    private ContractHost _host = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await ContractHost.StartAsync(postgres, f => f.Settings["M365:CompanyTenantId"] = CompanyTenant.ToString());
        await _host.MoveToAsync(2026, 10, 14, 9);
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private static CancellationToken Ct => ContractHost.Ct;

    private static void Problem(StaffClient.Answer answer, HttpStatusCode status, string code) =>
        Assert.Equal((status, code), (answer.Status, answer.Code));

    private static string Time(DateTimeOffset value) => Sikkerheit.Host.Platform.UtcTimeConverter.Format(value);

    [Fact]
    [Invariant("INV-001")]
    public async Task Inv001_portal_request_without_a_session_is_refused()
    {
        using var anonymous = StaffClient.Anonymous(_host.Factory);
        var answer = await StaffClient.Answer.ReadAsync(await anonymous.GetAsync("/api/v1/organizations", Ct), null);
        Problem(answer, HttpStatusCode.Unauthorized, ProblemCodes.SessionRequired);
    }

    [Fact]
    [Invariant("INV-002", Decision = "access token v1 of the own API carries amr (Реализация P1)")]
    public async Task Inv002_token_without_mfa_from_another_tenant_or_without_a_role_creates_no_session()
    {
        var options = new EntraOptions { TenantId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" };
        var user = Guid.NewGuid();
        string Access(string amr, string tid, string roles) =>
            $$"""{"tid":"{{tid}}","oid":"{{user}}","amr":{{amr}},"roles":{{roles}},"name":"Kari"}""";
        var cases = new (string Code, string Access, string Reason)[]
        {
            ("password-only", Access("""["pwd"]""", options.TenantId!, """["Admin"]"""), "mfa_required"),
            ("wia-or-mfa", Access("""["wiaormfa"]""", options.TenantId!, """["Admin"]"""), "mfa_required"),
            ("other-tenant", Access("""["pwd","mfa"]""", Guid.NewGuid().ToString(), """["Admin"]"""), "error"),
            ("no-role", Access("""["pwd","mfa"]""", options.TenantId!, "[]"), "no_role"),
        };
        foreach (var (code, access, reason) in cases)
        {
            _host.Factory.StaffIdentity.IssueTokens(code, options, access);
            using var browser = _host.Factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = true, AllowAutoRedirect = false });
            var callback = await SignInAsync(browser, code);
            Assert.Equal("/?signin=failed&reason=" + reason, callback.Headers.Location!.ToString());
            Problem(await StaffClient.Answer.ReadAsync(await browser.GetAsync("/api/v1/me", Ct), null), HttpStatusCode.Unauthorized,
                ProblemCodes.SessionRequired);
        }

        // The same checks accept a token with MFA, the company tenant and a role: the refusals above are not vacuous.
        _host.Factory.StaffIdentity.IssueTokens("good", options, Access("""["pwd","mfa"]""", options.TenantId!, """["Reader"]"""));
        using var good = _host.Factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = true, AllowAutoRedirect = false });
        await SignInAsync(good, "good");
        Assert.Equal(HttpStatusCode.OK, (await good.GetAsync("/api/v1/me", Ct)).StatusCode);
    }

    private static async Task<HttpResponseMessage> SignInAsync(HttpClient browser, string code)
    {
        var login = await browser.GetAsync("/auth/login", Ct);
        var state = QueryHelpers.ParseQuery(login.Headers.Location!.Query)["state"].ToString();
        return await browser.GetAsync($"/auth/callback?code={code}&state={Uri.EscapeDataString(state)}", Ct);
    }

    [Fact]
    [Invariant("INV-003")]
    public async Task Inv003_mutation_without_or_with_a_foreign_csrf_token_is_refused()
    {
        var org = await _host.OrganizationAsync();
        var finding = await _host.InsertFindingAsync(org);
        var path = $"/api/v1/organizations/{org}/findings/{finding}";
        var etag = await _host.ETagAsync(org, finding);
        var other = await _host.SignInAsync("Admin");
        Problem(await _host.Admin.SendAsync(HttpMethod.Patch, path, """{"workflowState":"in_progress"}""", null, ifMatch: etag, csrf: false),
            HttpStatusCode.Forbidden, ProblemCodes.CsrfFailed);
        Problem(await _host.Admin.SendAsync(HttpMethod.Patch, path, """{"workflowState":"in_progress"}""", null, ifMatch: etag,
            csrfOverride: other.Csrf), HttpStatusCode.Forbidden, ProblemCodes.CsrfFailed);
        Assert.Equal(etag, await _host.ETagAsync(org, finding));
    }

    [Fact]
    [Invariant("INV-004")]
    public async Task Inv004_reader_changes_nothing_and_technician_has_no_admin_operations()
    {
        var org = await _host.OrganizationAsync();
        var finding = await _host.InsertFindingAsync(org);
        var etag = await _host.ETagAsync(org, finding);
        var technician = await _host.SignInAsync("Technician");
        var reader = await _host.SignInAsync("Reader");
        var risk = new { decision = "risk_accepted", reason = "Kunden godtar risikoen", reviewAt = _host.Clock.GetUtcNow().AddDays(30) };
        Problem(await technician.PostAsync($"/api/v1/organizations/{org}/findings/{finding}/risk-decisions", risk, ifMatch: etag),
            HttpStatusCode.Forbidden, ProblemCodes.Forbidden);
        Problem(await technician.PostAsync($"/api/v1/organizations/{org}/lifecycle",
            new { action = "disable", reason = "Test", idempotencyKey = Guid.NewGuid() }), HttpStatusCode.Forbidden, ProblemCodes.Forbidden);
        Problem(await technician.PostAsync($"/api/v1/organizations/{org}/m365-connection/consent", new { tenantHint = Guid.NewGuid().ToString() }),
            HttpStatusCode.Forbidden, ProblemCodes.Forbidden);
        Problem(await technician.PostAsync($"/api/v1/organizations/{org}/policy-revisions",
            new { configuration = await _host.PolicyAsync(org) }, ifMatch: "\"1\""), HttpStatusCode.Forbidden, ProblemCodes.Forbidden);
        Problem(await reader.SendAsync(HttpMethod.Patch, $"/api/v1/organizations/{org}/findings/{finding}",
            """{"workflowState":"in_progress"}""", null, ifMatch: etag), HttpStatusCode.Forbidden, ProblemCodes.Forbidden);
        Problem(await reader.PostAsync($"/api/v1/organizations/{org}/collection-runs", new { idempotencyKey = Guid.NewGuid() }),
            HttpStatusCode.Forbidden, ProblemCodes.Forbidden);
        Assert.Equal(etag, await _host.ETagAsync(org, finding));
    }

    [Fact]
    [Invariant("INV-005")]
    public async Task Inv005_entity_of_another_organization_is_404()
    {
        var mine = await _host.OrganizationAsync("Min AS");
        var other = await _host.OrganizationAsync("Annen AS");
        var finding = await _host.InsertFindingAsync(other);
        Assert.Equal(HttpStatusCode.OK, (await _host.Admin.GetAsync($"/api/v1/organizations/{other}/findings/{finding}", "Finding")).Status);
        Problem(await _host.Admin.GetAsync($"/api/v1/organizations/{mine}/findings/{finding}"), HttpStatusCode.NotFound, ProblemCodes.NotFound);
        Problem(await _host.Admin.GetAsync($"/api/v1/organizations/{mine}/findings/{finding}/events"), HttpStatusCode.NotFound, ProblemCodes.NotFound);
        Problem(await _host.Admin.GetAsync($"/api/v1/organizations/{mine}/reports/{Guid.NewGuid()}/download"), HttpStatusCode.NotFound,
            ProblemCodes.NotFound);
    }

    [Fact]
    [Invariant("INV-006")]
    public async Task Inv006_cursor_of_another_organization_or_changed_cursor_is_refused()
    {
        var a = await _host.OrganizationAsync("A AS");
        var b = await _host.OrganizationAsync("B AS");
        await _host.InsertFindingAsync(a);
        await _host.InsertFindingAsync(a);
        var page = await _host.Admin.GetAsync($"/api/v1/organizations/{a}/findings?limit=1", "FindingPage");
        var cursor = page.Body.GetProperty("nextCursor").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await _host.Admin.GetAsync($"/api/v1/organizations/{a}/findings?limit=1&cursor={Uri.EscapeDataString(cursor)}",
            "FindingPage")).Status);
        Problem(await _host.Admin.GetAsync($"/api/v1/organizations/{b}/findings?limit=1&cursor={Uri.EscapeDataString(cursor)}"),
            HttpStatusCode.BadRequest, ProblemCodes.InvalidCursor);
        Problem(await _host.Admin.GetAsync($"/api/v1/organizations/{a}/findings?limit=1&severity=critical&cursor={Uri.EscapeDataString(cursor)}"),
            HttpStatusCode.BadRequest, ProblemCodes.InvalidCursor);
        Problem(await _host.Admin.GetAsync($"/api/v1/organizations/{a}/findings?limit=1&cursor={Uri.EscapeDataString(cursor[..^3] + "AAA")}"),
            HttpStatusCode.BadRequest, ProblemCodes.InvalidCursor);
    }

    [Fact]
    [Invariant("INV-011")]
    public async Task Inv011_consent_link_only_for_the_expected_tenant_and_not_for_the_company_without_the_flag()
    {
        var org = await _host.OrganizationAsync();
        Problem(await _host.Admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/consent", new { tenantHint = CompanyTenant.ToString() }),
            (HttpStatusCode)422, ProblemCodes.ValidationFailed);
        var allowed = await _host.Admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/consent",
            new { tenantHint = CompanyTenant.ToString(), allowCompanyTenant = true }, "ConsentStart");
        Assert.Equal(CompanyTenant.ToString(), allowed.Body.GetProperty("expectedTenantId").GetString());
        Assert.StartsWith($"https://login.microsoftonline.com/{CompanyTenant}/v2.0/adminconsent?", allowed.Body.GetProperty("consentUrl").GetString());
    }

    [Fact]
    [Invariant("INV-012")]
    public async Task Inv012_verification_before_consent_leaves_the_connection_unchanged()
    {
        var org = await _host.OrganizationAsync();
        var tenant = _host.Tenant();
        tenant.Consented = false;
        await _host.Admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/consent", new { tenantHint = tenant.TenantId.ToString() }, "ConsentStart");
        Problem(await _host.Admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/verify", new { }), (HttpStatusCode)422,
            ProblemCodes.ConsentNotGranted);
        var connection = await _host.Admin.GetAsync($"/api/v1/organizations/{org}/m365-connection", "TenantConnection");
        Assert.Equal(("consent_pending", JsonValueKind.Null),
            (connection.Body.GetProperty("status").GetString(), connection.Body.GetProperty("entraTenantId").ValueKind));
        // A token for the tenant whose /organization names another tenant does not activate either.
        tenant.Consented = true;
        tenant.OrganizationIdOverride = Guid.NewGuid();
        Problem(await _host.Admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/verify", new { }), (HttpStatusCode)422,
            ProblemCodes.ConsentNotGranted);
    }

    [Fact]
    [Invariant("INV-013")]
    public async Task Inv013_tenant_of_another_organization_or_another_tenant_than_the_active_one_is_refused()
    {
        var first = await _host.OrganizationAsync("Første AS");
        var second = await _host.OrganizationAsync("Andre AS");
        var tenant = _host.Tenant();
        await _host.ConnectAsync(first, tenant);
        Problem(await _host.Admin.PostAsync($"/api/v1/organizations/{second}/m365-connection/consent", new { tenantHint = tenant.TenantId.ToString() }),
            HttpStatusCode.Conflict, ProblemCodes.TenantConflict);
        Problem(await _host.Admin.PostAsync($"/api/v1/organizations/{first}/m365-connection/consent", new { tenantHint = Guid.NewGuid().ToString() }),
            HttpStatusCode.Conflict, ProblemCodes.TenantConflict);
    }

    [Fact]
    [Invariant("INV-014")]
    public async Task Inv014_collection_after_disconnect_and_verification_without_a_tenant_are_refused()
    {
        var org = await _host.OrganizationAsync();
        Problem(await _host.Admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/verify", new { }), HttpStatusCode.Conflict,
            ProblemCodes.ConnectionStateConflict);
        await _host.ConnectAsync(org, _host.Tenant());
        await _host.Admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/disconnect", new { }, "TenantConnection");
        Problem(await _host.Admin.PostAsync($"/api/v1/organizations/{org}/collection-runs", new { idempotencyKey = Guid.NewGuid() }),
            HttpStatusCode.Conflict, ProblemCodes.ConnectionStateConflict);
    }

    [Fact]
    [Invariant("INV-015")]
    public async Task Inv015_disconnect_writes_the_security_log_first_and_a_repeat_is_idempotent()
    {
        var org = await _host.OrganizationAsync();
        await _host.ConnectAsync(org, _host.Tenant());
        var first = await _host.Admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/disconnect", new { }, "TenantConnection");
        var second = await _host.Admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/disconnect", new { }, "TenantConnection");
        Assert.Equal((HttpStatusCode.OK, "disconnected"), (second.Status, second.Body.GetProperty("status").GetString()));
        Assert.Equal(first.Body.GetRawText(), second.Body.GetRawText());
        Assert.Single(_host.SecurityLog(org), r => r.GetProperty("action").GetString() == "m365.disconnect");
        Assert.Single(await _host.AuditAsync(org, "m365.disconnect"));
    }

    private async Task<StaffClient.Answer> PolicyAsync(Guid org, Action<JsonObject> change)
    {
        var configuration = await _host.PolicyAsync(org);
        change(configuration);
        return await _host.PolicyRevisionAsync(org, configuration, ifMatch: 1);
    }

    [Fact]
    [Invariant("INV-057")]
    public async Task Inv057_assessed_without_inputs_and_missing_required_checks_are_refused()
    {
        var org = await _host.OrganizationAsync();
        Problem(await PolicyAsync(org, c => c["checks"]!["WIN-010"]!["assessmentMode"] = "assessed"), (HttpStatusCode)422,
            ProblemCodes.PolicyInputsMissing);
        Problem(await PolicyAsync(org, c => c["activeCheckIds"] = new JsonArray(c["activeCheckIds"]!.AsArray()
            .Where(x => x!.GetValue<string>() != "WIN-011").Select(x => x!.DeepClone()).ToArray())), (HttpStatusCode)422,
            ProblemCodes.PolicyInputsMissing);
        Problem(await PolicyAsync(org, c => c["activeCheckIds"] = new JsonArray(c["activeCheckIds"]!.AsArray()
            .Where(x => x!.GetValue<string>() != "WIN-003").Select(x => x!.DeepClone()).ToArray())), (HttpStatusCode)422,
            ProblemCodes.PolicyInputsMissing);
        Assert.Single((await _host.Admin.GetAsync($"/api/v1/organizations/{org}/policy-revisions", "PolicyRevisionPage"))
            .Body.GetProperty("items").EnumerateArray());
    }

    [Fact]
    [Invariant("INV-058")]
    public async Task Inv058_contradicting_thresholds_are_refused()
    {
        var org = await _host.OrganizationAsync();
        Problem(await PolicyAsync(org, c => c["checks"]!["WIN-004"]!["parameters"]!["warnDays"] = 10), (HttpStatusCode)422,
            ProblemCodes.ValidationFailed);
        Problem(await PolicyAsync(org, c =>
        {
            c["checks"]!["M365-005"]!["parameters"]!["minGlobalAdmins"] = 4;
            c["checks"]!["M365-005"]!["parameters"]!["maxGlobalAdmins"] = 3;
        }), (HttpStatusCode)422, ProblemCodes.ValidationFailed);
        Problem(await PolicyAsync(org, c => c["agent"]!["maxBatchAgeDays"] = c["agent"]!["maxBufferDays"]!.GetValue<int>()),
            (HttpStatusCode)422, ProblemCodes.ValidationFailed);
    }

    [Fact]
    [Invariant("INV-059")]
    public async Task Inv059_workflow_change_and_risk_decision_without_if_match_are_refused()
    {
        var org = await _host.OrganizationAsync();
        var finding = await _host.InsertFindingAsync(org);
        var path = $"/api/v1/organizations/{org}/findings/{finding}";
        Problem(await _host.Admin.PatchAsync(path, new { workflowState = "in_progress" }), (HttpStatusCode)428, ProblemCodes.IfMatchRequired);
        Problem(await _host.Admin.PostAsync(path + "/risk-decisions",
            new { decision = "risk_accepted", reason = "Godtatt", reviewAt = _host.Clock.GetUtcNow().AddDays(30) }), (HttpStatusCode)428,
            ProblemCodes.IfMatchRequired);
    }

    [Fact]
    [Invariant("INV-060")]
    public async Task Inv060_stale_revision_is_refused()
    {
        var org = await _host.OrganizationAsync();
        var finding = await _host.InsertFindingAsync(org);
        var path = $"/api/v1/organizations/{org}/findings/{finding}";
        var etag = await _host.ETagAsync(org, finding);
        var technician = await _host.SignInAsync("Technician");
        // Two staff members change the due date at the same time: the second one has the old revision.
        Assert.Equal(HttpStatusCode.OK, (await _host.Admin.SendAsync(HttpMethod.Patch, path,
            $$"""{"dueAt":"{{Time(_host.Clock.GetUtcNow().AddDays(7))}}"}""", "Finding", ifMatch: etag)).Status);
        Problem(await technician.SendAsync(HttpMethod.Patch, path, $$"""{"dueAt":"{{Time(_host.Clock.GetUtcNow().AddDays(14))}}"}""", null,
            ifMatch: etag), HttpStatusCode.PreconditionFailed, ProblemCodes.RevisionMismatch);
        Problem(await _host.Admin.PostAsync(path + "/risk-decisions",
            new { decision = "risk_accepted", reason = "Godtatt", reviewAt = _host.Clock.GetUtcNow().AddDays(30) }, ifMatch: etag),
            HttpStatusCode.PreconditionFailed, ProblemCodes.RevisionMismatch);
    }

    [Fact]
    [Invariant("INV-062")]
    public async Task Inv062_risk_decision_only_for_open_and_withdrawal_only_from_a_decision()
    {
        var org = await _host.OrganizationAsync();
        var resolved = await _host.InsertFindingAsync(org, technicalState: "resolved");
        var open = await _host.InsertFindingAsync(org);
        Problem(await _host.Admin.PostAsync($"/api/v1/organizations/{org}/findings/{resolved}/risk-decisions",
            new { decision = "risk_accepted", reason = "Godtatt", reviewAt = _host.Clock.GetUtcNow().AddDays(30) },
            ifMatch: await _host.ETagAsync(org, resolved)), HttpStatusCode.Conflict, ProblemCodes.WorkflowTransitionForbidden);
        Problem(await _host.Admin.PostAsync($"/api/v1/organizations/{org}/findings/{open}/risk-decisions", new { decision = "withdrawn" },
            ifMatch: await _host.ETagAsync(org, open)), HttpStatusCode.Conflict, ProblemCodes.WorkflowTransitionForbidden);
    }

    [Fact]
    [Invariant("INV-063")]
    public async Task Inv063_review_date_outside_a_year_and_an_assignee_who_is_not_staff_are_refused()
    {
        var org = await _host.OrganizationAsync();
        var finding = await _host.InsertFindingAsync(org);
        var path = $"/api/v1/organizations/{org}/findings/{finding}";
        var etag = await _host.ETagAsync(org, finding);
        Problem(await _host.Admin.PostAsync(path + "/risk-decisions",
            new { decision = "risk_accepted", reason = "Godtatt", reviewAt = _host.Clock.GetUtcNow().AddDays(400) }, ifMatch: etag),
            (HttpStatusCode)422, ProblemCodes.ValidationFailed);
        Problem(await _host.Admin.PostAsync(path + "/risk-decisions",
            new { decision = "suppressed", reason = "Godtatt", reviewAt = _host.Clock.GetUtcNow().AddDays(-1) }, ifMatch: etag),
            (HttpStatusCode)422, ProblemCodes.ValidationFailed);
        var reader = await _host.SignInAsync("Reader");
        foreach (var assignee in new[] { Guid.NewGuid(), reader.EntraUserId })
        {
            Problem(await _host.Admin.SendAsync(HttpMethod.Patch, path, $$"""{"assigneeId":"{{assignee}}"}""", null, ifMatch: etag),
                (HttpStatusCode)422, ProblemCodes.ValidationFailed);
        }
    }

    [Fact]
    [Invariant("INV-064")]
    public async Task Inv064_every_risk_decision_writes_workflow_changed_with_the_actor()
    {
        var org = await _host.OrganizationAsync();
        var finding = await _host.InsertFindingAsync(org);
        var path = $"/api/v1/organizations/{org}/findings/{finding}";
        var accepted = await _host.Admin.PostAsync(path + "/risk-decisions",
            new { decision = "risk_accepted", reason = "Kunden godtar", reviewAt = _host.Clock.GetUtcNow().AddDays(30) }, "Finding",
            ifMatch: await _host.ETagAsync(org, finding));
        Assert.Equal(_host.Admin.EntraUserId.ToString(), accepted.Body.GetProperty("workflowDecidedBy").GetString());
        await _host.Admin.PostAsync(path + "/risk-decisions", new { decision = "withdrawn" }, "Finding", ifMatch: accepted.ETag);
        var events = (await _host.Admin.GetAsync(path + "/events", "FindingEventPage")).Body.GetProperty("items").EnumerateArray().ToList();
        Assert.Equal(2, events.Count);
        Assert.All(events, e => Assert.Equal(("workflow_changed", "manual_action", _host.Admin.EntraUserId.ToString()),
            (e.GetProperty("eventType").GetString(), e.GetProperty("cause").GetString(), e.GetProperty("actorId").GetString())));
    }

    [Fact]
    [Invariant("INV-066")]
    public async Task Inv066_assignment_change_is_audited_with_the_changed_fields_only()
    {
        var org = await _host.OrganizationAsync();
        var finding = await _host.InsertFindingAsync(org);
        var path = $"/api/v1/organizations/{org}/findings/{finding}";
        await _host.Admin.SendAsync(HttpMethod.Patch, path, $$"""{"assigneeId":"{{_host.Admin.EntraUserId}}"}""", "Finding",
            ifMatch: await _host.ETagAsync(org, finding));
        var audit = Assert.Single(await _host.AuditAsync(org, "finding.assignment_change"));
        var details = JsonDocument.Parse(audit.Details!).RootElement;
        Assert.Equal(["assigneeId"], details.EnumerateObject().Select(p => p.Name));
        Assert.Equal(_host.Admin.EntraUserId.ToString(), details.GetProperty("assigneeId").GetProperty("to").GetString());
        // A request that changes nothing writes no audit record.
        await _host.Admin.SendAsync(HttpMethod.Patch, path, $$"""{"assigneeId":"{{_host.Admin.EntraUserId}}"}""", "Finding",
            ifMatch: await _host.ETagAsync(org, finding));
        Assert.Single(await _host.AuditAsync(org, "finding.assignment_change"));
    }

    [Fact]
    [Invariant("INV-067")]
    public async Task Inv067_transitions_outside_the_table_are_refused()
    {
        var org = await _host.OrganizationAsync();
        Problem(await _host.LifecycleAsync(org, "schedule_deletion", exportWaived: true), HttpStatusCode.Conflict,
            ProblemCodes.LifecycleTransitionForbidden);
        Problem(await _host.LifecycleAsync(org, "enable"), HttpStatusCode.Conflict, ProblemCodes.LifecycleTransitionForbidden);
        await _host.LifecycleAsync(org, "disable");
        Problem(await _host.LifecycleAsync(org, "schedule_deletion"), HttpStatusCode.Conflict, ProblemCodes.LifecycleTransitionForbidden);
        Problem(await _host.LifecycleAsync(org, "cancel_deletion"), HttpStatusCode.Conflict, ProblemCodes.LifecycleTransitionForbidden);
        Assert.Equal("disabled", (await _host.Admin.GetAsync($"/api/v1/organizations/{org}", "Organization")).Body.GetProperty("status").GetString());
    }

    [Fact]
    [Invariant("INV-068")]
    public async Task Inv068_repeat_with_the_same_key_returns_the_first_result_without_a_second_effect()
    {
        var org = await _host.OrganizationAsync();
        var key = Guid.NewGuid();
        var first = await _host.LifecycleAsync(org, "disable", key);
        var repeat = await _host.LifecycleAsync(org, "disable", key);
        Assert.Equal((HttpStatusCode.OK, first.Body.GetRawText()), (repeat.Status, repeat.Body.GetRawText()));
        Assert.Single(_host.SecurityLog(org));
        Assert.Single(await _host.AuditAsync(org, "organization.lifecycle_change"));
    }

    [Fact]
    [Invariant("INV-069")]
    public async Task Inv069_same_key_with_another_body_is_refused()
    {
        var org = await _host.OrganizationAsync();
        var key = Guid.NewGuid();
        await _host.LifecycleAsync(org, "disable", key);
        Problem(await _host.LifecycleAsync(org, "enable", key), HttpStatusCode.Conflict, ProblemCodes.IdempotencyConflict);
        Assert.Equal("disabled", (await _host.Admin.GetAsync($"/api/v1/organizations/{org}", "Organization")).Body.GetProperty("status").GetString());
    }

    [Fact]
    [Invariant("INV-070")]
    public async Task Inv070_restrictive_transition_without_a_security_log_record_is_503_and_changes_nothing()
    {
        var org = await _host.OrganizationAsync();
        var connected = await _host.OrganizationAsync("Tilkoblet AS");
        await _host.ConnectAsync(connected, _host.Tenant());
        var scheduled = await _host.OrganizationAsync("Planlagt AS");
        await _host.LifecycleAsync(scheduled, "disable");
        await _host.LifecycleAsync(scheduled, "schedule_deletion", exportWaived: true);

        // The log storage goes away: the directory becomes a file.
        Directory.Delete(_host.Factory.SecurityLogDirectory, recursive: true);
        await File.WriteAllTextAsync(_host.Factory.SecurityLogDirectory, "not a directory", Ct);
        Problem(await _host.LifecycleAsync(org, "disable"), HttpStatusCode.ServiceUnavailable, ProblemCodes.TemporarilyUnavailable);
        Problem(await _host.LifecycleAsync(scheduled, "cancel_deletion"), HttpStatusCode.ServiceUnavailable, ProblemCodes.TemporarilyUnavailable);
        Problem(await _host.Admin.PostAsync($"/api/v1/organizations/{connected}/m365-connection/disconnect", new { }),
            HttpStatusCode.ServiceUnavailable, ProblemCodes.TemporarilyUnavailable);

        Assert.Equal("active", (await _host.Admin.GetAsync($"/api/v1/organizations/{org}", "Organization")).Body.GetProperty("status").GetString());
        Assert.Equal("deletion_scheduled", (await _host.Admin.GetAsync($"/api/v1/organizations/{scheduled}", "Organization"))
            .Body.GetProperty("status").GetString());
        Assert.Equal("active", (await _host.Admin.GetAsync($"/api/v1/organizations/{connected}/m365-connection", "TenantConnection"))
            .Body.GetProperty("status").GetString());
    }

    [Fact]
    [Invariant("INV-072")]
    public async Task Inv072_every_export_download_and_audit_read_is_audited()
    {
        var org = await _host.OrganizationAsync();
        var export = await _host.Admin.PostAsync($"/api/v1/organizations/{org}/exports", new { idempotencyKey = Guid.NewGuid() }, "OrganizationExport");
        await _host.RunJobsAsync();
        var download = $"/api/v1/organizations/{org}/exports/{export.Body.GetProperty("id").GetString()}/download";
        Assert.Equal(HttpStatusCode.OK, (await _host.Admin.DownloadAsync(download)).Status);
        Assert.Equal(HttpStatusCode.OK, (await _host.Admin.DownloadAsync(download)).Status);
        Assert.Equal(2, (await _host.AuditAsync(org, "organization_export.download")).Count);
        await _host.Admin.GetAsync($"/api/v1/organizations/{org}/audit-events", "AuditEventPage");
        await _host.Admin.GetAsync($"/api/v1/organizations/{org}/audit-events", "AuditEventPage");
        Assert.Equal(2, (await _host.AuditAsync(org, "audit_events.read")).Count);
    }

    private async Task<string> ReportAsync(Guid org, bool runJobs)
    {
        await _host.MoveToAsync(2026, 10, 14, 9);
        var created = await _host.Admin.PostAsync($"/api/v1/organizations/{org}/reports",
            new { periodStart = "2026-10-05T00:00:00+02:00", periodEnd = "2026-10-12T00:00:00+02:00", format = "html" }, "Report");
        Assert.Equal(HttpStatusCode.Accepted, created.Status);
        if (runJobs)
        {
            await _host.RunJobsAsync();
        }
        return created.Body.GetProperty("id").GetString()!;
    }

    [Fact]
    [Invariant("INV-073")]
    public async Task Inv073_file_before_ready_is_refused()
    {
        var org = await _host.OrganizationAsync();
        var report = await ReportAsync(org, runJobs: false);
        var queued = await _host.Admin.DownloadAsync($"/api/v1/organizations/{org}/reports/{report}/download");
        Assert.Equal((HttpStatusCode.Conflict, ProblemCodes.ResourceNotReady), (queued.Status, queued.Code));
        var export = await _host.Admin.PostAsync($"/api/v1/organizations/{org}/exports", new { idempotencyKey = Guid.NewGuid() }, "OrganizationExport");
        var early = await _host.Admin.DownloadAsync($"/api/v1/organizations/{org}/exports/{export.Body.GetProperty("id").GetString()}/download");
        Assert.Equal((HttpStatusCode.Conflict, ProblemCodes.ResourceNotReady), (early.Status, early.Code));
    }

    [Fact]
    [Invariant("INV-074")]
    public async Task Inv074_report_period_that_is_not_an_iso_week_of_the_organization_is_refused()
    {
        var org = await _host.OrganizationAsync();
        await _host.MoveToAsync(2026, 10, 21, 9);
        foreach (var (start, end) in new[]
                 {
                     ("2026-10-06T00:00:00+02:00", "2026-10-13T00:00:00+02:00"), // Tuesday to Tuesday
                     ("2026-10-05T00:00:00Z", "2026-10-12T00:00:00Z"), // Monday in UTC, not in Europe/Oslo
                     ("2026-10-05T00:00:00+02:00", "2026-10-19T00:00:00+02:00"), // two weeks
                 })
        {
            Problem(await _host.Admin.PostAsync($"/api/v1/organizations/{org}/reports", new { periodStart = start, periodEnd = end, format = "html" }),
                (HttpStatusCode)422, ProblemCodes.ValidationFailed);
        }
    }

    [Fact]
    [Invariant("INV-076")]
    public async Task Inv076_every_report_download_is_audited()
    {
        var org = await _host.OrganizationAsync();
        var report = await ReportAsync(org, runJobs: true);
        var path = $"/api/v1/organizations/{org}/reports/{report}/download";
        var reader = await _host.SignInAsync("Reader");
        Assert.Equal(HttpStatusCode.OK, (await _host.Admin.DownloadAsync(path)).Status);
        Assert.Equal(HttpStatusCode.OK, (await reader.DownloadAsync(path)).Status);
        var audits = await _host.AuditAsync(org, "report.download");
        Assert.Equal(2, audits.Count);
        Assert.Equal([_host.Admin.EntraUserId, reader.EntraUserId], audits.Select(a => a.ActorId!.Value));
    }

    [Fact]
    [Invariant("INV-177")]
    public async Task Inv177_hourly_refresh_redeems_the_refresh_token_and_a_refusal_ends_the_session()
    {
        var options = new EntraOptions { TenantId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" };
        string Access(Guid user, string amr, string roles) =>
            $$"""{"tid":"{{options.TenantId}}","oid":"{{user}}","amr":{{amr}},"roles":{{roles}},"name":"Kari"}""";
        // The refreshed tokens pass the same checks as at sign-in; each refresh returns a new token cache.
        StaffIdentity Refreshed(Guid user, string amr, string roles, byte cache)
        {
            using var claims = JsonDocument.Parse(Access(user, amr, roles));
            return StaffTokens.Verify(options, claims.RootElement, null, [cache]);
        }
        var refusals = new (string Case, Func<Guid, StaffIdentity> Refresh)[]
        {
            ("entra-refused", _ => throw new StaffSignInException("refresh_failed", "AADSTS700082 the refresh token has expired")),
            ("without-mfa", user => Refreshed(user, """["pwd"]""", """["Admin"]""", 9)),
            ("without-role", user => Refreshed(user, """["pwd","mfa"]""", "[]", 9)),
        };
        var day = 15;
        foreach (var (name, refusal) in refusals)
        {
            _host.Factory.StaffIdentity.RefreshedCaches.Clear();
            _host.Clock.SetLocal(ContractHost.Oslo, 2026, 10, day, 9);
            _host.Factory.StaffIdentity.IssueTokens(name, options, Access(Guid.NewGuid(), """["pwd","mfa"]""", """["Admin"]"""));
            using var browser = _host.Factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = true, AllowAutoRedirect = false });
            await SignInAsync(browser, name);
            var me = async () => await StaffClient.Answer.ReadAsync(await browser.GetAsync("/api/v1/me", Ct), null);
            _host.Factory.StaffIdentity.Refresh = user => Refreshed(user, """["pwd","mfa"]""", """["Admin"]""", 7);

            // Within the hour the session is used as it is; after 60 minutes the refresh token is redeemed once.
            _host.Clock.SetLocal(ContractHost.Oslo, 2026, 10, day, 9, 40);
            Assert.Equal(HttpStatusCode.OK, (await me()).Status);
            Assert.Empty(_host.Factory.StaffIdentity.RefreshedCaches);
            _host.Clock.SetLocal(ContractHost.Oslo, 2026, 10, day, 10, 5);
            Assert.Equal(HttpStatusCode.OK, (await me()).Status);
            _host.Clock.SetLocal(ContractHost.Oslo, 2026, 10, day, 10, 50);
            Assert.Equal(HttpStatusCode.OK, (await me()).Status);
            Assert.Equal([[1, 2, 3]], _host.Factory.StaffIdentity.RefreshedCaches);

            // The next refresh is refused: the session is gone, also for the following request.
            _host.Factory.StaffIdentity.Refresh = refusal;
            _host.Clock.SetLocal(ContractHost.Oslo, 2026, 10, day, 11, 6);
            Problem(await me(), HttpStatusCode.Unauthorized, ProblemCodes.SessionRequired);
            Assert.Equal([[1, 2, 3], [7]], _host.Factory.StaffIdentity.RefreshedCaches);
            Problem(await me(), HttpStatusCode.Unauthorized, ProblemCodes.SessionRequired);
            day++;
        }
    }

    [Fact]
    [Invariant("INV-188")]
    public async Task Inv188_every_risk_decision_including_withdrawn_creates_one_risk_decision_row()
    {
        var org = await _host.OrganizationAsync();
        var finding = await _host.InsertFindingAsync(org);
        var path = $"/api/v1/organizations/{org}/findings/{finding}/risk-decisions";
        var reviewAt = _host.Clock.GetUtcNow().AddDays(30);
        var accepted = await _host.Admin.PostAsync(path, new { decision = "risk_accepted", reason = "Kunden godtar", reviewAt }, "Finding",
            ifMatch: await _host.ETagAsync(org, finding));
        var withdrawn = await _host.Admin.PostAsync(path, new { decision = "withdrawn" }, "Finding", ifMatch: accepted.ETag);
        await _host.Admin.PostAsync(path, new { decision = "suppressed", reason = "Testkonto", reviewAt }, "Finding", ifMatch: withdrawn.ETag);

        await using var scope = await _host.Scopes.OrganizationAsync(org, Ct);
        var decisions = await scope.Db.RiskDecisions.AsNoTracking().Where(d => d.FindingId == finding).OrderBy(d => d.Id).ToListAsync(Ct);
        Assert.Equal(["risk_accepted", "withdrawn", "suppressed"], decisions.Select(d => d.Decision));
        var events = await scope.Db.FindingEvents.AsNoTracking().Where(e => e.FindingId == finding).ToDictionaryAsync(e => e.Id, Ct);
        Assert.Equal(3, events.Count);
        Assert.All(decisions, d => Assert.Equal(("workflow_changed", "manual_action"),
            (events[d.FindingEventId].EventType, events[d.FindingEventId].Cause)));
        Assert.Equal(3, decisions.Select(d => d.FindingEventId).Distinct().Count());
        Assert.All(decisions, d => Assert.Equal(_host.Admin.EntraUserId, d.DecidedBy));
    }

    [Fact]
    [Invariant("INV-190")]
    public async Task Inv190_report_of_the_current_or_a_future_week_is_refused()
    {
        var org = await _host.OrganizationAsync();
        var reports = $"/api/v1/organizations/{org}/reports";
        // Wednesday 14 October: the week of 12 October is not over, the week of 19 October has not begun.
        foreach (var (start, end) in new[]
                 {
                     ("2026-10-12T00:00:00+02:00", "2026-10-19T00:00:00+02:00"),
                     ("2026-10-19T00:00:00+02:00", "2026-10-26T00:00:00+02:00"),
                 })
        {
            Problem(await _host.Admin.PostAsync(reports, new { periodStart = start, periodEnd = end, format = "html" }), (HttpStatusCode)422,
                ProblemCodes.ValidationFailed);
        }
        Assert.Empty((await _host.Admin.GetAsync(reports, "ReportPage")).Body.GetProperty("items").EnumerateArray());
        var completed = await _host.Admin.PostAsync(reports,
            new { periodStart = "2026-10-05T00:00:00+02:00", periodEnd = "2026-10-12T00:00:00+02:00", format = "html" }, "Report");
        Assert.Equal(HttpStatusCode.Accepted, completed.Status);
    }

    [Fact]
    [Invariant("INV-191")]
    public async Task Inv191_repeated_report_request_regenerates_failed_and_returns_ready_unchanged()
    {
        var org = await _host.OrganizationAsync();
        var id = await ReportAsync(org, runJobs: false);
        // The generation failed for good: the report is failed and its job ended.
        await using (var scope = await _host.Scopes.OrganizationAsync(org, Ct))
        {
            await using var failed = new NpgsqlCommand("""
                update report set state = 'failed', failure_code = 'generation_error' where id = @id;
                update job set state = 'failed', completed_at = @now, attempts = 10 where type = 'report_generate' and input_id = @input;
                """, scope.Connection, scope.Transaction);
            failed.Parameters.AddWithValue("id", Guid.Parse(id));
            failed.Parameters.AddWithValue("input", id);
            failed.Parameters.AddWithValue("now", _host.Clock.GetUtcNow());
            await failed.ExecuteNonQueryAsync(Ct);
            await scope.CommitAsync(Ct);
        }
        var again = await ReportAsync(org, runJobs: false);
        Assert.Equal(id, again);
        var page = $"/api/v1/organizations/{org}/reports";
        var queued = (await _host.Admin.GetAsync(page, "ReportPage")).Body.GetProperty("items").EnumerateArray().Single();
        Assert.Equal("queued", queued.GetProperty("state").GetString());
        await _host.RunJobsAsync();
        var ready = (await _host.Admin.GetAsync(page, "ReportPage")).Body.GetProperty("items").EnumerateArray().Single();
        Assert.Equal((id, "ready"), (ready.GetProperty("id").GetString()!, ready.GetProperty("state").GetString()));

        // A ready report is returned as it is: no new generation, no new row.
        var repeat = await _host.Admin.PostAsync(page,
            new { periodStart = "2026-10-05T00:00:00+02:00", periodEnd = "2026-10-12T00:00:00+02:00", format = "html" }, "Report");
        Assert.Equal(ready.GetRawText(), repeat.Body.GetRawText());
        await using var platform = await _host.Scopes.PlatformAsync(Ct);
        var job = await platform.Db.Jobs.AsNoTracking().SingleAsync(j => j.Type == "report_generate" && j.InputId == id, Ct);
        Assert.Equal("succeeded", job.State);
    }

    [Fact]
    [Invariant("INV-196")]
    public async Task Inv196_assessed_mode_for_the_deferred_check_is_refused()
    {
        var org = await _host.OrganizationAsync();
        Problem(await PolicyAsync(org, c => c["checks"]!["M365-007"]!["assessmentMode"] = "assessed"), (HttpStatusCode)422,
            ProblemCodes.PolicyInputsMissing);
        Assert.Single((await _host.Admin.GetAsync($"/api/v1/organizations/{org}/policy-revisions", "PolicyRevisionPage"))
            .Body.GetProperty("items").EnumerateArray());
        // The informational mode of the same check is accepted.
        Assert.Equal(HttpStatusCode.Created,
            (await PolicyAsync(org, c => c["checks"]!["M365-007"]!["assessmentMode"] = "informational")).Status);
    }
}
