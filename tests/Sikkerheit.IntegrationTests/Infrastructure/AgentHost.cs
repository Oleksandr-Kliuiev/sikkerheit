using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;

namespace Sikkerheit.IntegrationTests.Infrastructure;

/// <summary>
/// One service instance with an Admin session, an organization and an enrollment key, and the agents that register with it.
/// The data is read straight from the organization scope when a test needs to see what the service wrote.
/// </summary>
public sealed class AgentHost : IAsyncDisposable
{
    public const string Oslo = "Europe/Oslo";
    private readonly List<FakeAgent> _agents = [];

    private AgentHost(ApiFactory factory) => Factory = factory;

    public ApiFactory Factory { get; }
    public StaffClient Admin { get; private set; } = null!;
    public Guid Org { get; private set; }
    public Guid KeyId { get; private set; }
    public string KeySecret { get; private set; } = "";
    public DbScopes Scopes => Factory.Services.GetRequiredService<DbScopes>();
    public TestClock Clock => Factory.Clock;
    public static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>The service with an organization and one enrollment key; «now» is a working day morning in Oslo.</summary>
    public static async Task<AgentHost> StartAsync(PostgresFixture postgres, Action<ApiFactory>? configure = null,
        string? securityLogDirectory = null)
    {
        var factory = await ApiFactory.CreateAsync(postgres, securityLogDirectory);
        configure?.Invoke(factory);
        var host = new AgentHost(factory);
        factory.Clock.SetLocal(Oslo, 2026, 10, 14, 9);
        host.Admin = await StaffClient.SignInAsync(factory, "Admin");
        var created = await host.Admin.PostAsync("/api/v1/organizations", new { name = "Fjord AS", timezone = Oslo, reportLanguage = "nb" }, "Organization");
        Assert.Equal(HttpStatusCode.Created, created.Status);
        host.Org = Guid.Parse(created.Body.GetProperty("id").GetString()!);
        (host.KeyId, host.KeySecret) = await host.CreateKeyAsync("RMM");
        return host;
    }

    public ValueTask DisposeAsync()
    {
        foreach (var agent in _agents)
        {
            agent.Dispose();
        }
        return Factory.DisposeAsync();
    }

    public async Task<(Guid Id, string Secret)> CreateKeyAsync(string label)
    {
        var created = await Admin.PostAsync($"/api/v1/organizations/{Org}/enrollment-keys", new { label }, "EnrollmentKey");
        Assert.Equal(HttpStatusCode.Created, created.Status);
        return (Guid.Parse(created.Body.GetProperty("id").GetString()!), created.Body.GetProperty("enrollmentKey").GetString()!);
    }

    /// <summary>Moves «now» and signs the Admin in again (staff sessions end after an hour without requests).</summary>
    public async Task MoveToAsync(DateTimeOffset moment)
    {
        Clock.Set(moment);
        Admin = await StaffClient.SignInAsync(Factory, "Admin");
    }

    public FakeAgent NewAgent(string name = "PC-ANNE", Guid? installationId = null, string? smbiosUuid = null, string? machineGuid = null)
    {
        var agent = new FakeAgent(Factory, KeySecret, installationId, name, smbiosUuid ?? "4C4C4544-0042-3510-8058-B4C04F4E3732",
            machineGuid ?? "8C1F7A2E-3B4D-4E5F-9A6B-7C8D9E0F1A2B");
        _agents.Add(agent);
        return agent;
    }

    /// <summary>An agent that registered and holds a session.</summary>
    public async Task<FakeAgent> EnrolledAsync(string name = "PC-ANNE", Guid? installationId = null)
    {
        var agent = NewAgent(name, installationId);
        await agent.EnrollOkAsync();
        await agent.StartSessionAsync();
        return agent;
    }

    public Task<StaffClient.Answer> LifecycleAsync(string action) =>
        Admin.PostAsync($"/api/v1/organizations/{Org}/lifecycle", new { action, reason = "Kunden har sagt opp avtalen", idempotencyKey = Guid.NewGuid() }, "Organization");

    /// <summary>The newest revision as an object to edit, and its version.</summary>
    public async Task<(System.Text.Json.Nodes.JsonObject Configuration, int Version)> PolicyAsync()
    {
        var page = await Admin.GetAsync($"/api/v1/organizations/{Org}/policy-revisions", "PolicyRevisionPage");
        var newest = page.Body.GetProperty("items")[0];
        return (System.Text.Json.Nodes.JsonNode.Parse(newest.GetProperty("configuration").GetRawText())!.AsObject(),
            newest.GetProperty("version").GetInt32());
    }

    /// <summary>A new policy revision made from the newest one by the edit; returns the answer.</summary>
    public async Task<StaffClient.Answer> NewPolicyAsync(Action<System.Text.Json.Nodes.JsonObject> edit)
    {
        var (configuration, version) = await PolicyAsync();
        edit(configuration);
        return await Admin.SendAsync(HttpMethod.Post, $"/api/v1/organizations/{Org}/policy-revisions",
            new System.Text.Json.Nodes.JsonObject { ["configuration"] = configuration.DeepClone() }.ToJsonString(), "PolicyRevision",
            ifMatch: $"\"{version}\"");
    }

    public sealed record ReleaseEntry(int Branch, int Ubr, string Kb, string Kind, string? SecurityMonth, string? ReleaseAt = null);

    /// <summary>importWindowsReleases with manual entries of the month (they are drafts).</summary>
    public Task<StaffClient.Answer> ImportReleasesAsync(string month, params ReleaseEntry[] entries) =>
        Admin.PostAsync("/api/v1/windows-releases/imports", new
        {
            source = "manual", securityMonth = month,
            entries = entries.Select(e => new
            {
                branchBuild = e.Branch, ubr = e.Ubr, kb = e.Kb, releaseAt = e.ReleaseAt ?? month + "-13T17:00:00Z", kind = e.Kind,
                securityMonth = e.SecurityMonth, autoOffered = true,
            }),
        }, "WindowsReleaseMonth");

    public Task<StaffClient.Answer> VerifyMonthAsync(string month, bool noNewReleases = false, StaffClient? client = null) =>
        (client ?? Admin).PostAsync($"/api/v1/windows-releases/months/{month}/verify", new { noNewReleases }, "WindowsReleaseMonth");

    /// <summary>Queues patch_level_sweep for the organization (the scheduler does it daily) and runs the queued jobs.</summary>
    public async Task SweepAsync(string period)
    {
        await using (var platform = await Scopes.PlatformAsync(Ct))
        {
            await JobQueue.EnqueueAsync(platform, "patch_level_sweep", Org, null, period, Clock.GetUtcNow(), Ct);
            await platform.CommitAsync(Ct);
        }
        await RunJobsAsync();
    }

    public async Task RunJobsAsync()
    {
        var runner = Factory.Services.GetRequiredService<JobRunner>();
        while (await runner.RunOnceAsync(Ct))
        {
        }
    }

    public async Task<T> ReadAsync<T>(Func<DbScope, Task<T>> read)
    {
        await using var scope = await Scopes.OrganizationAsync(Org, Ct);
        return await read(scope);
    }

    public Task<Device> DeviceAsync(Guid id) => ReadAsync(scope => scope.Db.Devices.AsNoTracking().SingleAsync(d => d.Id == id, Ct));

    public Task<List<Finding>> FindingsAsync(string? checkId = null) => ReadAsync(scope =>
        scope.Db.Findings.AsNoTracking().Where(f => checkId == null || f.CheckId == checkId).ToListAsync(Ct));

    /// <summary>Events as «eventType/cause» in time order, optionally of one check.</summary>
    public Task<List<string>> EventsAsync(string? checkId = null) => ReadAsync(async scope =>
    {
        var findings = await scope.Db.Findings.AsNoTracking().Where(f => checkId == null || f.CheckId == checkId).Select(f => f.Id).ToListAsync(Ct);
        return await scope.Db.FindingEvents.AsNoTracking().Where(e => findings.Contains(e.FindingId))
            .OrderBy(e => e.OccurredAt).ThenBy(e => e.Id).Select(e => e.EventType + "/" + e.Cause).ToListAsync(Ct);
    });

    /// <summary>Assessments of a check, newest first.</summary>
    public Task<List<Assessment>> AssessmentsAsync(string checkId, string? scope = null) => ReadAsync(s =>
        s.Db.Assessments.AsNoTracking().Where(a => a.CheckId == checkId && (scope == null || a.AssessmentScope == scope))
            .OrderByDescending(a => a.EvaluatedAt).ThenByDescending(a => a.Id).ToListAsync(Ct));

    /// <summary>Current assessments of a check made by the revision of the policy.</summary>
    public Task<List<Assessment>> AssessmentsForPolicyAsync(string checkId, int policyVersion) => ReadAsync(s =>
        s.Db.Assessments.AsNoTracking().Where(a => a.CheckId == checkId && a.AssessmentScope == "current"
                                                   && a.EvaluatedPolicyVersion == policyVersion).ToListAsync(Ct));

    public Task<List<AuditEvent>> AuditAsync(string action) => ReadAsync(s =>
        s.Db.AuditEvents.AsNoTracking().Where(e => e.Action == action).OrderBy(e => e.OccurredAt).ToListAsync(Ct));

    public Task<List<Subject>> SubjectsAsync(string type) => ReadAsync(s => s.Db.Subjects.AsNoTracking().Where(x => x.Type == type).ToListAsync(Ct));

    public IReadOnlyList<JsonElement> SecurityLog() =>
        (Directory.Exists(Factory.SecurityLogDirectory) ? Directory.GetFiles(Factory.SecurityLogDirectory) : [])
        .Select(f => JsonDocument.Parse(File.ReadAllText(f)).RootElement.Clone())
        .Where(r => r.GetProperty("organizationId").GetString() == Org.ToString())
        .ToList();
}
