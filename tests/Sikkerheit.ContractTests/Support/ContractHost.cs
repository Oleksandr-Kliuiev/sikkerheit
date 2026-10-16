using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests.Support;

/// <summary>One service instance on its own database with an Admin session and the steps the contract tests share.</summary>
public sealed class ContractHost : IAsyncDisposable
{
    public const string Oslo = "Europe/Oslo";
    public const string GlobalAdministrator = "62e90394-69f5-4237-9190-012177145e10";

    private ContractHost(ApiFactory factory) => Factory = factory;

    public ApiFactory Factory { get; }
    public StaffClient Admin { get; private set; } = null!;
    public DbScopes Scopes => Factory.Services.GetRequiredService<DbScopes>();
    public TestClock Clock => Factory.Clock;
    public FakeGraph Graph => Factory.Graph;
    public static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <param name="configure">Changes the instance before it starts, e.g. its settings.</param>
    public static async Task<ContractHost> StartAsync(PostgresFixture postgres, Action<ApiFactory>? configure = null,
        string? securityLogDirectory = null)
    {
        var factory = await ApiFactory.CreateAsync(postgres, securityLogDirectory);
        configure?.Invoke(factory);
        var host = new ContractHost(factory);
        host.Admin = await StaffClient.SignInAsync(factory, "Admin");
        return host;
    }

    public ValueTask DisposeAsync() => Factory.DisposeAsync();

    public Task<StaffClient> SignInAsync(params string[] roles) => StaffClient.SignInAsync(Factory, roles);

    /// <summary>Moves «now» and signs the Admin in again (sessions end after an hour without requests).</summary>
    public async Task MoveToAsync(int year, int month, int day, int hour, int minute = 0)
    {
        Clock.SetLocal(Oslo, year, month, day, hour, minute);
        Admin = await StaffClient.SignInAsync(Factory, "Admin");
    }

    public async Task<Guid> OrganizationAsync(string name = "Kontrakt AS", string language = "nb")
    {
        var created = await Admin.PostAsync("/api/v1/organizations", new { name, timezone = Oslo, reportLanguage = language }, "Organization");
        Assert.Equal(HttpStatusCode.Created, created.Status);
        return Guid.Parse(created.Body.GetProperty("id").GetString()!);
    }

    public Task<StaffClient.Answer> LifecycleAsync(Guid org, string action, Guid? key = null, bool? exportWaived = null,
        string reason = "Kunden har sagt opp avtalen", StaffClient? client = null) =>
        (client ?? Admin).PostAsync($"/api/v1/organizations/{org}/lifecycle", exportWaived is null
            ? new { action, reason, idempotencyKey = key ?? Guid.NewGuid() }
            : new { action, reason, idempotencyKey = key ?? Guid.NewGuid(), exportWaived }, "Organization");

    /// <summary>A synthetic tenant of the fake Graph; by default with two global administrators who have FIDO2.</summary>
    public FakeTenant Tenant(bool twoAdmins = true)
    {
        var tenant = Graph.AddTenant();
        if (twoAdmins)
        {
            for (var i = 0; i < 2; i++)
            {
                tenant.Assignments.Add((tenant.AddUser("ga" + i, methods: "fido2").Id, GlobalAdministrator, false));
            }
        }
        return tenant;
    }

    /// <summary>Consent link for the tenant and the verification by the service's own token: the connection is active.</summary>
    public async Task ConnectAsync(Guid org, FakeTenant tenant)
    {
        var consent = await Admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/consent",
            new { tenantHint = tenant.TenantId.ToString() }, "ConsentStart");
        Assert.Equal(HttpStatusCode.Created, consent.Status);
        var verified = await Admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/verify", new { }, "TenantConnection");
        Assert.Equal("active", verified.Body.GetProperty("status").GetString());
    }

    public async Task RunJobsAsync()
    {
        var runner = Factory.Services.GetRequiredService<JobRunner>();
        while (await runner.RunOnceAsync(Ct))
        {
        }
    }

    /// <summary>An unplanned collection run and every job it queues; returns the run.</summary>
    public async Task<CollectionRun> CollectAsync(Guid org)
    {
        var requested = await Admin.PostAsync($"/api/v1/organizations/{org}/collection-runs", new { idempotencyKey = Guid.NewGuid() },
            "CollectionRun");
        Assert.Equal(HttpStatusCode.Accepted, requested.Status);
        await RunJobsAsync();
        return await RunAsync(org, Guid.Parse(requested.Body.GetProperty("id").GetString()!));
    }

    /// <summary>The capability status of one module in a run.</summary>
    public static string? Module(CollectionRun run, string module) =>
        JsonDocument.Parse(run.Capabilities).RootElement.EnumerateArray()
            .Single(c => c.GetProperty("module").GetString() == module).GetProperty("status").GetString();

    public async Task<CollectionRun> RunAsync(Guid org, Guid runId)
    {
        await using var scope = await Scopes.OrganizationAsync(org, Ct);
        return await scope.Db.CollectionRuns.AsNoTracking().SingleAsync(r => r.Id == runId, Ct);
    }

    public async Task<CollectionRun> LastRunAsync(Guid org)
    {
        await using var scope = await Scopes.OrganizationAsync(org, Ct);
        return await scope.Db.CollectionRuns.AsNoTracking().OrderByDescending(r => r.QueuedAt).FirstAsync(Ct);
    }

    public async Task<List<Finding>> FindingsAsync(Guid org, string? checkId = null)
    {
        await using var scope = await Scopes.OrganizationAsync(org, Ct);
        return await scope.Db.Findings.AsNoTracking().Where(f => checkId == null || f.CheckId == checkId).ToListAsync(Ct);
    }

    /// <summary>Events as «eventType/cause» in time order, optionally of one check.</summary>
    public async Task<List<string>> EventsAsync(Guid org, string? checkId = null)
    {
        await using var scope = await Scopes.OrganizationAsync(org, Ct);
        var findings = await scope.Db.Findings.AsNoTracking().Where(f => checkId == null || f.CheckId == checkId)
            .Select(f => f.Id).ToListAsync(Ct);
        return await scope.Db.FindingEvents.AsNoTracking().Where(e => findings.Contains(e.FindingId))
            .OrderBy(e => e.OccurredAt).ThenBy(e => e.Id).Select(e => e.EventType + "/" + e.Cause).ToListAsync(Ct);
    }

    /// <summary>Current assessments of a check, newest first.</summary>
    public async Task<List<Host.Data.Assessment>> AssessmentsAsync(Guid org, string checkId)
    {
        await using var scope = await Scopes.OrganizationAsync(org, Ct);
        return await scope.Db.Assessments.AsNoTracking().Where(a => a.CheckId == checkId)
            .OrderByDescending(a => a.EvaluatedAt).ThenByDescending(a => a.Id).ToListAsync(Ct);
    }

    public async Task<List<Observation>> ObservationsAsync(Guid org, Guid runId)
    {
        await using var scope = await Scopes.OrganizationAsync(org, Ct);
        return await scope.Db.Observations.AsNoTracking().Where(o => o.CollectionRunId == runId).ToListAsync(Ct);
    }

    public async Task<Guid> SubjectIdAsync(Guid org, string key)
    {
        await using var scope = await Scopes.OrganizationAsync(org, Ct);
        return await scope.Db.Subjects.AsNoTracking().Where(s => s.Key == key).Select(s => s.Id).SingleAsync(Ct);
    }

    public async Task<List<AuditEvent>> AuditAsync(Guid org, string action)
    {
        await using var scope = await Scopes.OrganizationAsync(org, Ct);
        return await scope.Db.AuditEvents.AsNoTracking().Where(e => e.Action == action).OrderBy(e => e.OccurredAt).ToListAsync(Ct);
    }

    /// <summary>Security log records of the organization (files of the development log).</summary>
    public IReadOnlyList<JsonElement> SecurityLog(Guid org) =>
        (Directory.Exists(Factory.SecurityLogDirectory) ? Directory.GetFiles(Factory.SecurityLogDirectory) : [])
        .Select(f => JsonDocument.Parse(File.ReadAllText(f)).RootElement.Clone())
        .Where(r => r.GetProperty("organizationId").GetString() == org.ToString())
        .ToList();

    public async Task<JsonObject> PolicyAsync(Guid org)
    {
        var page = await Admin.GetAsync($"/api/v1/organizations/{org}/policy-revisions", "PolicyRevisionPage");
        return JsonNode.Parse(page.Body.GetProperty("items")[0].GetProperty("configuration").GetRawText())!.AsObject();
    }

    public Task<StaffClient.Answer> PolicyRevisionAsync(Guid org, JsonObject configuration, int ifMatch) =>
        Admin.SendAsync(HttpMethod.Post, $"/api/v1/organizations/{org}/policy-revisions",
            new JsonObject { ["configuration"] = configuration.DeepClone() }.ToJsonString(), null, ifMatch: $"\"{ifMatch}\"");

    /// <summary>A user subject with an open finding, written directly in the organization scope (no collection needed).</summary>
    public async Task<Guid> InsertFindingAsync(Guid org, string checkId = "M365-001", string technicalState = "open",
        string severity = "warning", DateTimeOffset? openedAt = null, bool openedEvent = false)
    {
        var now = openedAt ?? Clock.GetUtcNow();
        await using var scope = await Scopes.OrganizationAsync(org, Ct);
        var subject = new Subject
        {
            OrganizationId = org, Id = Guid.CreateVersion7(), Type = "user", Key = Guid.NewGuid().ToString(),
            DisplayName = "kari@fjord.example", FirstSeenAt = now, LastSeenAt = now,
        };
        var finding = new Finding
        {
            OrganizationId = org, Id = Guid.CreateVersion7(), SubjectId = subject.Id, CheckId = checkId, TechnicalState = technicalState,
            WorkflowState = "new", AssessmentResult = technicalState == "open" ? "fail" : "pass", Severity = severity,
            Quality = "fresh_fail", LatestObservedAt = now, OpenedAt = now, ResolvedAt = technicalState == "open" ? null : now,
        };
        scope.Db.Subjects.Add(subject);
        scope.Db.Findings.Add(finding);
        if (openedEvent)
        {
            scope.Db.FindingEvents.Add(new FindingEvent
            {
                OrganizationId = org, FindingId = finding.Id, Id = Guid.CreateVersion7(), EventType = "opened", Cause = "source_change",
                OccurredAt = now,
            });
        }
        await scope.CommitAsync(Ct);
        return finding.Id;
    }

    /// <summary>The ETag (revision) of a finding as getFinding returns it.</summary>
    public async Task<string> ETagAsync(Guid org, Guid finding) =>
        (await Admin.GetAsync($"/api/v1/organizations/{org}/findings/{finding}", "Finding")).ETag!;
}
