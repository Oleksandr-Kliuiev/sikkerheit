using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sikkerheit.Contracts;
using Sikkerheit.ContractTests.Invariants;
using Sikkerheit.ContractTests.Support;
using Sikkerheit.Host.Jobs;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests;

/// <summary>Records enforced by the background jobs: the job table, leases, the scheduler and the handlers.</summary>
[Enforcement("worker")]
public sealed class WorkerInvariantTests(PostgresFixture postgres) : IAsyncLifetime
{
    private ContractHost _host = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await ContractHost.StartAsync(postgres);
        await _host.MoveToAsync(2026, 10, 7, 10);
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private static CancellationToken Ct => ContractHost.Ct;

    private async Task EnqueueAsync(string type, Guid? org, string period)
    {
        await using var platform = await _host.Scopes.PlatformAsync(Ct);
        await JobQueue.EnqueueAsync(platform, type, org, null, period, _host.Clock.GetUtcNow(), Ct);
        await platform.CommitAsync(Ct);
    }

    private Task<List<Host.Data.Job>> JobsAsync(string type) => JobsAsync(_host, type);

    private static async Task<List<Host.Data.Job>> JobsAsync(ContractHost host, string type)
    {
        await using var platform = await host.Scopes.PlatformAsync(Ct);
        return await platform.Db.Jobs.AsNoTracking().Where(j => j.Type == type).ToListAsync(Ct);
    }

    private Scheduler SecondInstance() =>
        new(_host.Scopes, _host.Clock, NullLogger<Scheduler>.Instance);

    [Fact]
    [Invariant("INV-065")]
    public async Task Inv065_expired_review_returns_the_finding_to_new_once()
    {
        var org = await _host.OrganizationAsync();
        var finding = await _host.InsertFindingAsync(org);
        await _host.Admin.PostAsync($"/api/v1/organizations/{org}/findings/{finding}/risk-decisions",
            new { decision = "risk_accepted", reason = "Kunden godtar til neste uke", reviewAt = _host.Clock.GetUtcNow().AddDays(1) }, "Finding",
            ifMatch: await _host.ETagAsync(org, finding));
        await _host.MoveToAsync(2026, 10, 9, 10);
        await EnqueueAsync("review_expiry", org, "2026-10-09T08");
        await _host.RunJobsAsync();
        await EnqueueAsync("review_expiry", org, "2026-10-09T09");
        await _host.RunJobsAsync();
        Assert.Equal("new", (await _host.FindingsAsync(org)).Single().WorkflowState);
        var events = (await _host.Admin.GetAsync($"/api/v1/organizations/{org}/findings/{finding}/events", "FindingEventPage"))
            .Body.GetProperty("items").EnumerateArray()
            .Select(e => (e.GetProperty("eventType").GetString(), e.GetProperty("cause").GetString())).ToList();
        Assert.Equal([("workflow_changed", "manual_action"), ("workflow_changed", "review_expired")], events);
    }

    [Fact]
    [Invariant("INV-071")]
    public async Task Inv071_retention_purge_deletes_in_the_registry_order_and_writes_a_summary()
    {
        var tenant = _host.Tenant();
        tenant.SecurityDefaults = true;
        tenant.GrantPolicies.Clear();
        var alice = tenant.AddUser("alice");
        var org = await _host.OrganizationAsync();
        await _host.ConnectAsync(org, tenant);
        await _host.RunJobsAsync();
        tenant.Users[tenant.Users.IndexOf(alice)] = alice with { Methods = ["microsoftAuthenticator"] };
        await _host.CollectAsync(org);
        Assert.Equal("resolved", (await _host.FindingsAsync(org, "M365-001")).Single().TechnicalState);

        // Thirteen months later the resolved finding and its events are past the term of 12 months.
        await _host.MoveToAsync(2027, 11, 20, 3);
        await EnqueueAsync("retention_purge", org, "2027-11-20");
        await _host.RunJobsAsync();
        Assert.Equal("succeeded", (await JobsAsync("retention_purge")).Single().State);
        Assert.Empty(await _host.FindingsAsync(org, "M365-001"));
        var summary = Assert.Single(await _host.AuditAsync(org, "retention.purge_summary"));
        var deleted = JsonDocument.Parse(summary.Details!).RootElement.GetProperty("deleted");
        Assert.Equal(Catalog.RetentionPurgeOrder.Order(), deleted.EnumerateObject().Select(p => p.Name).Order());
        // The events, assessments and findings went in one run: the foreign keys allow that only in the registry order.
        // The job deletes table by table through the owner modules in the same order: every registry table is a step of
        // the job, in order (jsonb does not keep the order of the summary keys).
        var source = File.ReadAllText(Path.Combine(InvariantRegistry.Root, "src", "Sikkerheit.Host", "Jobs", "DataLifecycleJobs.cs"));
        var purge = source[source.IndexOf("class RetentionPurgeJob", StringComparison.Ordinal)..];
        var steps = System.Text.RegularExpressions.Regex.Matches(purge, @"\[""([a-z_]+)""\] = (?:await|0)")
            .Select(m => m.Groups[1].Value).ToList();
        Assert.Equal(Catalog.RetentionPurgeOrder, steps);
        Assert.True(deleted.GetProperty("finding_event").GetInt32() >= 2);
        Assert.True(deleted.GetProperty("finding").GetInt32() >= 1);
        Assert.True(deleted.GetProperty("observation").GetInt32() >= 1);
    }

    [Fact]
    [Invariant("INV-075")]
    public async Task Inv075_report_without_a_translation_fails_without_another_language()
    {
        var org = await _host.OrganizationAsync("Nynorsk AS", "nn");
        // A finding of a rule version whose nn text does not exist yet.
        await _host.InsertFindingAsync(org, checkId: "M365-999", openedAt: new DateTimeOffset(2026, 9, 29, 8, 0, 0, TimeSpan.Zero),
            openedEvent: true);
        var created = await _host.Admin.PostAsync($"/api/v1/organizations/{org}/reports",
            new { periodStart = "2026-09-28T00:00:00+02:00", periodEnd = "2026-10-05T00:00:00+02:00", format = "html" }, "Report");
        Assert.Equal(HttpStatusCode.Accepted, created.Status);
        await _host.RunJobsAsync();
        var report = (await _host.Admin.GetAsync($"/api/v1/organizations/{org}/reports", "ReportPage")).Body.GetProperty("items")[0];
        Assert.Equal(("failed", "translation_missing"), (report.GetProperty("state").GetString(), report.GetProperty("failureCode").GetString()));
        Assert.Single(await _host.AuditAsync(org, "report.failed"));
        Assert.Contains(_host.Factory.Logs.Entries, e => e.Level == LogLevel.Error && e.Message.Contains("translation_missing", StringComparison.Ordinal));
        Assert.False(Directory.Exists(Path.Combine(_host.Factory.FilesDirectory, "reports", org.ToString())));
    }

    [Fact]
    [Invariant("INV-077")]
    public async Task Inv077_periodic_job_of_one_period_is_created_once_by_two_instances()
    {
        var org = await _host.OrganizationAsync();
        await _host.MoveToAsync(2026, 10, 19, 6, 30);
        var first = _host.Factory.Services.GetRequiredService<Scheduler>();
        await Task.WhenAll(first.RunOnceAsync(Ct), SecondInstance().RunOnceAsync(Ct));
        await Task.WhenAll(first.RunOnceAsync(Ct), SecondInstance().RunOnceAsync(Ct));
        var weekly = (await JobsAsync("weekly_report")).Where(j => j.OrganizationId == org).Select(j => j.PeriodKey).ToList();
        Assert.Contains("2026-W42", weekly);
        Assert.Equal(weekly.Distinct().Count(), weekly.Count);
    }

    [Fact]
    [Invariant("INV-078")]
    public async Task Inv078_expired_lease_is_captured_again_and_the_old_owner_has_no_effect()
    {
        var org = await _host.OrganizationAsync();
        await EnqueueAsync("freshness_sweep", org, "2026-10-07T08");
        Guid id;
        await using (var platform = await _host.Scopes.PlatformAsync(Ct))
        {
            // The old owner paused longer than its lease.
            await using var paused = new NpgsqlCommand("""
                update job set state = 'running', lease_owner = 'paused:1', lease_token = 1, lease_until = @expired, attempts = 1
                where type = 'freshness_sweep' returning id
                """, platform.Connection, platform.Transaction);
            paused.Parameters.AddWithValue("expired", _host.Clock.GetUtcNow().AddMinutes(-1));
            id = (Guid)(await paused.ExecuteScalarAsync(Ct))!;
            await platform.CommitAsync(Ct);
        }
        Assert.True(await _host.Factory.Services.GetRequiredService<JobRunner>().RunOnceAsync(Ct));
        var job = (await JobsAsync("freshness_sweep")).Single();
        Assert.Equal(("succeeded", 2L), (job.State, job.LeaseToken));
        var completed = job.CompletedAt;

        var stale = new JobLease(id, 1, "freshness_sweep", org, null, "2026-10-07T08");
        await using (var scope = await _host.Scopes.OrganizationAsync(org, Ct))
        {
            Assert.False(await stale.HoldAsync(scope, Ct));
            await Assert.ThrowsAsync<JobLeaseLostException>(() => stale.CompleteAsync(scope, Ct));
        }
        Assert.Equal(completed, (await JobsAsync("freshness_sweep")).Single().CompletedAt);
    }

    [Fact]
    [Invariant("INV-079")]
    public async Task Inv079_unplanned_collection_joins_the_open_run()
    {
        var org = await _host.OrganizationAsync();
        var tenant = _host.Tenant();
        tenant.SecurityDefaults = true;
        await _host.ConnectAsync(org, tenant);
        // The verification queued a run that has not started; two more requests join it.
        var first = await _host.Admin.PostAsync($"/api/v1/organizations/{org}/collection-runs", new { idempotencyKey = Guid.NewGuid() }, "CollectionRun");
        var second = await _host.Admin.PostAsync($"/api/v1/organizations/{org}/collection-runs", new { idempotencyKey = Guid.NewGuid() }, "CollectionRun");
        Assert.Equal(first.Body.GetProperty("id").GetString(), second.Body.GetProperty("id").GetString());
        // The daily scheduled job comes while the run is still open: it does not start a second one.
        await _host.MoveToAsync(2026, 10, 7, 9, 58);
        await EnqueueAsync("m365_collect", org, "2026-10-07");
        Assert.True(await _host.Factory.Services.GetRequiredService<JobRunner>().RunOnceAsync(Ct));
        Assert.Equal("succeeded", (await JobsAsync("m365_collect")).Single(j => j.PeriodKey == "2026-10-07").State);
        await _host.MoveToAsync(2026, 10, 7, 10, 5);
        await _host.RunJobsAsync();
        await using var scope = await _host.Scopes.OrganizationAsync(org, Ct);
        var runs = await scope.Db.CollectionRuns.AsNoTracking().ToListAsync(Ct);
        Assert.Equal([first.Body.GetProperty("id").GetString()], runs.Select(r => r.Id.ToString()));
        Assert.Equal("completed", runs.Single().State);
    }

    [Fact]
    [Invariant("INV-084")]
    public async Task Inv084_job_without_an_organization_is_unique_by_type_and_period()
    {
        await _host.MoveToAsync(2026, 10, 8, 7, 45);
        var first = _host.Factory.Services.GetRequiredService<Scheduler>();
        await Task.WhenAll(first.RunOnceAsync(Ct), SecondInstance().RunOnceAsync(Ct));
        await EnqueueAsync("teams_digest", null, "2026-10-08");
        Assert.Equal(["2026-10-08"], (await JobsAsync("teams_digest")).Select(j => j.PeriodKey));
        await _host.RunJobsAsync();
        Assert.Single(_host.Factory.Teams.Requests);
    }

    /// <summary>An organization connected to a tenant without Security Defaults: M365-003 opens a critical finding.</summary>
    private static async Task<Guid> CriticalOrganizationAsync(ContractHost host, string name = "Kritisk AS")
    {
        var tenant = host.Tenant();
        tenant.PerUserMfa.Clear();
        var org = await host.OrganizationAsync(name);
        await host.ConnectAsync(org, tenant);
        await host.RunJobsAsync();
        Assert.Contains(await host.FindingsAsync(org, "M365-003"), f => f.Severity == "critical");
        return org;
    }

    private static async Task RequeueAsync(ContractHost host, string type)
    {
        await using var platform = await host.Scopes.PlatformAsync(Ct);
        await using var requeue = new NpgsqlCommand("""
            update job set state = 'queued', attempts = 0, lease_owner = null, lease_until = null, completed_at = null,
                next_attempt_at = @now
            where type = @type
            """, platform.Connection, platform.Transaction);
        requeue.Parameters.AddWithValue("now", host.Clock.GetUtcNow().AddMinutes(-1));
        requeue.Parameters.AddWithValue("type", type);
        await requeue.ExecuteNonQueryAsync(Ct);
        await platform.CommitAsync(Ct);
    }

    private static async Task<Host.Data.CollectionRun> OpenRunAsync(ContractHost host, Guid org, TimeSpan age)
    {
        var started = host.Clock.GetUtcNow() - age;
        var run = new Host.Data.CollectionRun
        {
            OrganizationId = org, Id = Guid.CreateVersion7(), Trigger = "scheduled", State = "running", QueuedAt = started,
            StartedAt = started, Capabilities = "[]", PolicyVersion = 1,
        };
        await using var scope = await host.Scopes.OrganizationAsync(org, Ct);
        scope.Db.CollectionRuns.Add(run);
        await scope.CommitAsync(Ct);
        return run;
    }

    private static async Task<List<Host.Data.CollectionRun>> RunsAsync(ContractHost host, Guid org)
    {
        await using var scope = await host.Scopes.OrganizationAsync(org, Ct);
        return await scope.Db.CollectionRuns.AsNoTracking().OrderBy(r => r.QueuedAt).ToListAsync(Ct);
    }

    [Fact]
    [Invariant("INV-183")]
    public async Task Inv183_a_run_open_for_7_hours_is_closed_and_exactly_one_new_run_starts()
    {
        var tenant = _host.Tenant();
        tenant.SecurityDefaults = true;
        var org = await _host.OrganizationAsync();
        await _host.ConnectAsync(org, tenant);
        await _host.RunJobsAsync();
        // The process died during a run 7 hours ago: it stays «running» without observations.
        var crashed = await OpenRunAsync(_host, org, TimeSpan.FromHours(7));
        var before = (await RunsAsync(_host, org)).Select(r => r.Id).ToHashSet();

        await EnqueueAsync("m365_collect", org, "2026-10-07");
        await _host.RunJobsAsync();
        var runs = await RunsAsync(_host, org);
        var closed = runs.Single(r => r.Id == crashed.Id);
        Assert.Equal(("failed", "run_timeout"), (closed.State, closed.FailureCode));
        Assert.Empty(await _host.ObservationsAsync(org, crashed.Id));
        var started = Assert.Single(runs, r => !before.Contains(r.Id));
        Assert.Equal(("scheduled", "completed"), (started.Trigger, started.State));
        Assert.NotEmpty(await _host.ObservationsAsync(org, started.Id));

        // A run open for less than 6 hours is another job's: the scheduled job ends without collecting.
        var young = await OpenRunAsync(_host, org, TimeSpan.FromHours(2));
        await EnqueueAsync("m365_collect", org, "2026-10-08");
        await _host.RunJobsAsync();
        runs = await RunsAsync(_host, org);
        Assert.Equal(before.Count + 2, runs.Count);
        Assert.Equal("running", runs.Single(r => r.Id == young.Id).State);
        Assert.Equal("succeeded", (await JobsAsync("m365_collect")).Single(j => j.PeriodKey == "2026-10-08").State);
    }

    [Fact]
    [Invariant("INV-185")]
    public async Task Inv185_recalculation_writes_no_further_batch_after_losing_its_lease()
    {
        await using var host = await ContractHost.StartAsync(postgres, f => f.Settings["Jobs:RecalculateBatchSize"] = "1");
        await host.MoveToAsync(2026, 10, 7, 10);
        var tenant = host.Tenant();
        tenant.SecurityDefaults = true;
        tenant.AddUser("anna", methods: "fido2");
        tenant.AddUser("bjorn");
        var org = await host.OrganizationAsync();
        await host.ConnectAsync(org, tenant);
        await host.RunJobsAsync();

        // Another worker takes the job over while the first batch commits: its first write moves the lease token.
        var owner = new NpgsqlConnectionStringBuilder(host.Factory.ConnectionString)
        {
            Username = "sikkerheit_owner", Password = "owner-test",
        }.ConnectionString;
        await using (var connection = new NpgsqlConnection(owner))
        {
            await connection.OpenAsync(Ct);
            await using var trigger = new NpgsqlCommand("""
                create function public.take_over_recalculation() returns trigger language plpgsql as $$
                begin
                    update job set lease_token = lease_token + 1 where type = 'recalculate_policy' and state = 'running';
                    return null;
                end $$;
                create trigger take_over_recalculation after insert on assessment
                    for each statement execute function public.take_over_recalculation();
                """, connection);
            await trigger.ExecuteNonQueryAsync(Ct);
        }
        var policy = await host.PolicyAsync(org);
        policy["checks"]!["M365-001"]!["parameters"]!["phoneMethodsAccepted"] = false;
        Assert.Equal(HttpStatusCode.Created, (await host.PolicyRevisionAsync(org, policy, 1)).Status);
        await host.RunJobsAsync();

        await using var scope = await host.Scopes.OrganizationAsync(org, Ct);
        var recalculated = await scope.Db.Assessments.AsNoTracking().Where(a => a.EvaluatedPolicyVersion == 2)
            .Select(a => a.SubjectId).Distinct().CountAsync(Ct);
        var subjects = await scope.Db.Subjects.AsNoTracking().CountAsync(Ct);
        Assert.True(subjects > 1, "the recalculation must need several batches");
        Assert.Equal(1, recalculated);
        Assert.NotEqual("succeeded", Assert.Single(await JobsAsync(host, "recalculate_policy")).State);
    }

    [Fact]
    [Invariant("INV-186")]
    public async Task Inv186_a_repeated_digest_job_with_the_sent_mark_sends_nothing()
    {
        await CriticalOrganizationAsync(_host);
        await _host.MoveToAsync(2026, 10, 8, 7, 45);
        await _host.Factory.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
        await _host.RunJobsAsync();
        Assert.Single(_host.Factory.Teams.Requests);

        // The job is captured again after the webhook accepted the digest.
        await RequeueAsync(_host, "teams_digest");
        await _host.RunJobsAsync();
        Assert.Single(_host.Factory.Teams.Requests);
    }

    [Fact]
    [Invariant("INV-186")]
    public async Task Inv186_without_an_accepting_webhook_the_period_is_not_marked()
    {
        await using var host = await ContractHost.StartAsync(postgres, f => f.Settings["Teams:WebhookUrl"] = "");
        await host.MoveToAsync(2026, 10, 7, 10);
        await CriticalOrganizationAsync(host);
        await host.MoveToAsync(2026, 10, 8, 7, 45);
        await host.Factory.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
        await host.RunJobsAsync();
        Assert.Empty(host.Factory.Teams.Requests);
        await using var platform = await host.Scopes.PlatformAsync(Ct);
        await using var marks = new NpgsqlCommand("select count(*) from teams_digest", platform.Connection, platform.Transaction);
        Assert.Equal(0L, await marks.ExecuteScalarAsync(Ct));
    }

    [Fact]
    [Invariant("INV-187")]
    public async Task Inv187_untrusted_names_reach_teams_only_as_text_runs()
    {
        const string name = "Fjord [klikk her](https://evil.example) **AS**";
        await CriticalOrganizationAsync(_host, name);
        await _host.MoveToAsync(2026, 10, 8, 7, 45);
        await _host.Factory.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
        await _host.RunJobsAsync();
        var (_, body) = Assert.Single(_host.Factory.Teams.Requests);
        var card = JsonDocument.Parse(body).RootElement.GetProperty("attachments")[0].GetProperty("content");
        var blocks = card.GetProperty("body").EnumerateArray().ToList();
        Assert.All(blocks, b => Assert.Equal("RichTextBlock", b.GetProperty("type").GetString()));
        Assert.All(blocks, b => Assert.All(b.GetProperty("inlines").EnumerateArray(), i => Assert.Equal("TextRun", i.GetProperty("type").GetString())));
        Assert.Contains(blocks, b => b.GetProperty("inlines")[0].GetProperty("text").GetString() == name);
        // The only address in the card is the portal's own; none is built from the data.
        var urls = card.TryGetProperty("actions", out var actions)
            ? actions.EnumerateArray().Select(a => a.GetProperty("url").GetString()).ToList() : [];
        Assert.All(urls, u => Assert.StartsWith("https://portal.test/", u, StringComparison.Ordinal));
    }

    [Fact]
    [Invariant("INV-192")]
    public async Task Inv192_a_ready_report_is_never_rewritten_and_a_lost_file_is_rebuilt_from_its_snapshot()
    {
        var tenant = _host.Tenant();
        tenant.SecurityDefaults = true;
        var kari = tenant.AddUser("kari");
        var org = await _host.OrganizationAsync();
        await _host.ConnectAsync(org, tenant);
        await _host.RunJobsAsync();
        await _host.MoveToAsync(2026, 10, 12, 9);
        var created = await _host.Admin.PostAsync($"/api/v1/organizations/{org}/reports",
            new { periodStart = "2026-10-05T00:00:00+02:00", periodEnd = "2026-10-12T00:00:00+02:00", format = "html" }, "Report");
        var reportId = Guid.Parse(created.Body.GetProperty("id").GetString()!);
        await _host.RunJobsAsync();
        var download = $"/api/v1/organizations/{org}/reports/{reportId}/download";
        var original = (await _host.Admin.DownloadAsync(download)).Text;

        await using (var scope = await _host.Scopes.OrganizationAsync(org, Ct))
        {
            await using var update = new NpgsqlCommand("update report set snapshot = '{}'::jsonb where id = @id", scope.Connection, scope.Transaction);
            update.Parameters.AddWithValue("id", reportId);
            Assert.Equal("P0001", (await Assert.ThrowsAsync<PostgresException>(() => update.ExecuteNonQueryAsync(Ct))).SqlState);
        }
        // Later facts do not change a closed week: Kari registers MFA, a new run resolves the finding, the file is lost.
        tenant.Users[tenant.Users.IndexOf(kari)] = kari with { Methods = ["microsoftAuthenticator"] };
        await _host.CollectAsync(org);
        var file = Assert.Single(Directory.GetFiles(Path.Combine(_host.Factory.FilesDirectory, "reports", org.ToString()),
            reportId + ".html", SearchOption.AllDirectories));
        File.Delete(file);
        var rebuilt = await _host.Admin.DownloadAsync(download);
        Assert.Equal(HttpStatusCode.OK, rebuilt.Status);
        Assert.Equal(original, rebuilt.Text);
    }

    [Fact]
    [Invariant("INV-194")]
    public async Task Inv194_weekly_reports_start_with_the_creation_week_and_catch_up_at_most_four_weeks()
    {
        var early = await _host.OrganizationAsync("Tidlig AS");
        await _host.MoveToAsync(2026, 11, 19, 12);
        var late = await _host.OrganizationAsync("Sen AS");
        // Seven weeks after «Tidlig» was created and in the first week of «Sen»: Monday 23 November, 07:00.
        await _host.MoveToAsync(2026, 11, 23, 7);
        await _host.Factory.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
        var jobs = await JobsAsync("weekly_report");
        Assert.Equal(["2026-W44", "2026-W45", "2026-W46", "2026-W47"],
            jobs.Where(j => j.OrganizationId == early).Select(j => j.PeriodKey).Order());
        Assert.Equal(["2026-W47"], jobs.Where(j => j.OrganizationId == late).Select(j => j.PeriodKey));
    }
}
