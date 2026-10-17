using Npgsql;
using Sikkerheit.ContractTests.Support;
using Sikkerheit.Host.Reports;
using Sikkerheit.IntegrationTests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Sikkerheit.ContractTests;

public sealed class FindingWorkSummaryTests(PostgresFixture postgres)
{
    [Fact]
    public async Task Digest_reminds_only_overdue_actionable_work_and_never_exposes_subjects()
    {
        await using var host = await ContractHost.StartAsync(postgres);
        var org = await host.OrganizationAsync("Fjord AS");
        var overdue = await host.InsertFindingAsync(org);
        var accepted = await host.InsertFindingAsync(org);
        var suppressed = await host.InsertFindingAsync(org);
        var resolved = await host.InsertFindingAsync(org, technicalState: "resolved");
        var future = await host.InsertFindingAsync(org);
        var retired = await host.InsertFindingAsync(org);
        var inactive = await host.OrganizationAsync("Inactive AS");
        await host.InsertFindingAsync(inactive);
        var ct = TestContext.Current.CancellationToken;
        await using (var scope = await host.Scopes.OrganizationAsync(org, ct))
        {
            await using var update = new NpgsqlCommand("""
                update finding set due_at = @past;
                update finding set workflow_state = 'risk_accepted' where id = @accepted;
                update finding set workflow_state = 'suppressed' where id = @suppressed;
                update finding set due_at = @future where id = @future_id;
                update subject set retired_at = @now where id = (select subject_id from finding where id = @retired)
                """, scope.Connection, scope.Transaction);
            update.Parameters.AddWithValue("past", host.Clock.GetUtcNow().AddDays(-1));
            update.Parameters.AddWithValue("accepted", accepted);
            update.Parameters.AddWithValue("suppressed", suppressed);
            update.Parameters.AddWithValue("future", host.Clock.GetUtcNow().AddDays(1));
            update.Parameters.AddWithValue("future_id", future);
            update.Parameters.AddWithValue("retired", retired);
            update.Parameters.AddWithValue("now", host.Clock.GetUtcNow());
            await update.ExecuteNonQueryAsync(ct);
            await scope.CommitAsync(ct);
        }
        await using (var scope = await host.Scopes.OrganizationAsync(inactive, ct))
        {
            await using var update = new NpgsqlCommand("update organization set status = 'disabled', disabled_at = @past; update finding set due_at = @past", scope.Connection, scope.Transaction);
            update.Parameters.AddWithValue("past", host.Clock.GetUtcNow().AddDays(-1));
            await update.ExecuteNonQueryAsync(ct);
            await scope.CommitAsync(ct);
        }
        var items = await ActivatorUtilities.CreateInstance<TeamsDigestJob>(host.Factory.Services)
            .CollectAsync(host.Clock.GetUtcNow().AddDays(-1), host.Clock.GetUtcNow(), ct);
        var reminder = Assert.Single(items, item => item.Kind == "overdue");
        Assert.Equal(org, reminder.OrganizationId);
        Assert.Equal("1 avvik har passert arbeidsfristen", reminder.Text);
        Assert.DoesNotContain("kari", reminder.Text, StringComparison.OrdinalIgnoreCase);
        _ = overdue;
        _ = resolved;
    }
}
