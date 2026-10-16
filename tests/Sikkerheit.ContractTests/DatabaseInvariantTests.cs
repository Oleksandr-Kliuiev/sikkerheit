using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.ContractTests.Invariants;
using Sikkerheit.ContractTests.Support;
using Sikkerheit.Host.Jobs;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests;

/// <summary>Records enforced by PostgreSQL row-level security and the request scopes (02 «Разделение клиентов»).</summary>
[Enforcement("db_rls")]
public sealed class DatabaseInvariantTests(PostgresFixture postgres) : IAsyncLifetime
{
    private ContractHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await ContractHost.StartAsync(postgres);

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private static CancellationToken Ct => ContractHost.Ct;

    /// <summary>A raw connection of the application role to this instance's database, outside DbScopes.</summary>
    private async Task<NpgsqlConnection> ConnectAsync()
    {
        var connection = new NpgsqlConnection(_host.Factory.ConnectionString);
        await connection.OpenAsync(Ct);
        return connection;
    }

    private static async Task<long> ScalarAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        return Convert.ToInt64(await command.ExecuteScalarAsync(Ct), System.Globalization.CultureInfo.InvariantCulture);
    }

    private async Task<long> FindingCountAsync(Guid org)
    {
        await using var scope = await _host.Scopes.OrganizationAsync(org, Ct);
        return await scope.Db.Findings.LongCountAsync(Ct);
    }

    [Fact]
    [Invariant("INV-007")]
    public async Task Inv007_query_without_a_scope_returns_no_client_rows()
    {
        var org = await _host.OrganizationAsync();
        await _host.InsertFindingAsync(org);
        await using var connection = await ConnectAsync();
        Assert.Equal(0, await ScalarAsync(connection, null, "select count(*) from finding"));
        Assert.Equal(0, await ScalarAsync(connection, null, "select count(*) from organization"));
        Assert.Equal(1, await FindingCountAsync(org));
    }

    [Fact]
    [Invariant("INV-008", Decision = "0.3.1: a refused statement (read-only transaction) counts as protection, external review F15")]
    public async Task Inv008_changes_in_the_read_all_scope_or_of_another_organization_change_nothing()
    {
        var a = await _host.OrganizationAsync("A AS");
        var b = await _host.OrganizationAsync("B AS");
        await _host.InsertFindingAsync(a);
        await _host.InsertFindingAsync(b);

        // Through DbScopes the read-all scope is READ ONLY: the statement is refused.
        await using (var all = await _host.Scopes.ReadAllAsync(Ct))
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => all.Db.Database.ExecuteSqlRawAsync("delete from finding", Ct));
            Assert.Equal(PostgresErrorCodes.ReadOnlySqlTransaction, error.SqlState);
        }
        // Without the READ ONLY guard the policies themselves still give 0 rows: write policies need the organization scope.
        await using (var connection = await ConnectAsync())
        await using (var transaction = await connection.BeginTransactionAsync(Ct))
        {
            await ScalarAsync(connection, transaction, "select count(*) from (select set_config('app.scope_all', 'on', true)) s");
            Assert.Equal(2, await ScalarAsync(connection, transaction, "select count(*) from finding"));
            await using var delete = new NpgsqlCommand("delete from finding", connection, transaction);
            Assert.Equal(0, await delete.ExecuteNonQueryAsync(Ct));
            await using var update = new NpgsqlCommand("update finding set severity = 'critical'", connection, transaction);
            Assert.Equal(0, await update.ExecuteNonQueryAsync(Ct));
            await transaction.CommitAsync(Ct);
        }
        // In the scope of A the rows of B are out of reach.
        await using (var scope = await _host.Scopes.OrganizationAsync(a, Ct))
        {
            Assert.Equal(0, await scope.Db.Database.ExecuteSqlInterpolatedAsync($"delete from finding where organization_id = {b}", Ct));
            Assert.Equal(0, await scope.Db.Database.ExecuteSqlInterpolatedAsync($"update organization set name = 'x' where id = {b}", Ct));
            await scope.CommitAsync(Ct);
        }
        Assert.Equal((1, 1), (await FindingCountAsync(a), await FindingCountAsync(b)));
    }

    [Fact]
    [Invariant("INV-009")]
    public async Task Inv009_read_all_scope_only_read_only_and_only_in_the_listed_components()
    {
        var org = await _host.OrganizationAsync();
        await using (var connection = await ConnectAsync())
        await using (var transaction = await connection.BeginTransactionAsync(Ct))
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() =>
                ScalarAsync(connection, transaction, "select count(*) from (select app.set_scope_all()) s"));
            Assert.Contains("READ ONLY", error.MessageText, StringComparison.Ordinal);
        }
        // An UPDATE in the scheduler's read-all transaction is refused.
        await using (var all = await _host.Scopes.ReadAllAsync(Ct))
        {
            await Assert.ThrowsAsync<PostgresException>(() =>
                all.Db.Database.ExecuteSqlInterpolatedAsync($"update organization set name = 'x' where id = {org}", Ct));
        }
        Assert.Equal("Kontrakt AS", (await _host.Admin.GetAsync($"/api/v1/organizations/{org}", "Organization")).Body.GetProperty("name").GetString());

        // Static check of 02: the read-all scope is opened only by the closed list of components, and no code sets app.*.
        var allowed = new[]
        {
            "Data/DbScopes.cs", "Organizations/OrganizationEndpoints.cs", "Assessment/FindingEndpoints.cs", "Jobs/Scheduler.cs",
            "Reports/TeamsDigest.cs", "Operations/RestoreReplay.cs",
        };
        var source = Path.Combine(InvariantRegistry.Root, "src", "Sikkerheit.Host");
        var files = Directory.EnumerateFiles(source, "*.cs", SearchOption.AllDirectories)
            .Select(f => (Path: Path.GetRelativePath(source, f).Replace('\\', '/'), Text: File.ReadAllText(f))).ToList();
        Assert.Equal([], files.Where(f => f.Text.Contains("ReadAllAsync(", StringComparison.Ordinal)).Select(f => f.Path)
            .Except(allowed).ToList());
        Assert.Equal([], files.Where(f => Regex.IsMatch(f.Text, @"set_config\s*\(")).Select(f => f.Path).ToList());
        Assert.Equal(["Data/DbScopes.cs"], files.Where(f => f.Text.Contains("app.set_scope", StringComparison.Ordinal))
            .Select(f => f.Path).ToList());
    }

    [Fact]
    [Invariant("INV-010")]
    public async Task Inv010_job_reads_only_its_own_organization()
    {
        var a = await _host.OrganizationAsync("A AS");
        var b = await _host.OrganizationAsync("B AS");
        var report = Guid.CreateVersion7();
        await using (var scope = await _host.Scopes.OrganizationAsync(a, Ct))
        {
            scope.Db.Reports.Add(new Host.Data.Report
            {
                OrganizationId = a, Id = report, PeriodStart = new DateTimeOffset(2026, 10, 4, 22, 0, 0, TimeSpan.Zero),
                PeriodEnd = new DateTimeOffset(2026, 10, 11, 22, 0, 0, TimeSpan.Zero), Timezone = ContractHost.Oslo, Language = "nb",
                Format = "html", State = "queued", CreatedAt = _host.Clock.GetUtcNow(),
            });
            await scope.CommitAsync(Ct);
        }
        // report_generate of organization B with the report id of A.
        await using (var platform = await _host.Scopes.PlatformAsync(Ct))
        {
            await JobQueue.EnqueueAsync(platform, "report_generate", b, report.ToString(), null, _host.Clock.GetUtcNow(), Ct);
            await platform.CommitAsync(Ct);
        }
        await _host.RunJobsAsync();
        await using (var scope = await _host.Scopes.OrganizationAsync(a, Ct))
        {
            var row = await scope.Db.Reports.AsNoTracking().SingleAsync(r => r.Id == report, Ct);
            Assert.Equal(("queued", null), (row.State, row.BlobKey));
        }
        await using (var platform = await _host.Scopes.PlatformAsync(Ct))
        {
            Assert.Equal("succeeded", await platform.Db.Jobs.Where(j => j.Type == "report_generate" && j.OrganizationId == b)
                .Select(j => j.State).SingleAsync(Ct));
        }
        Assert.False(Directory.Exists(Path.Combine(_host.Factory.FilesDirectory, "reports", b.ToString())));
        Assert.False(Directory.Exists(Path.Combine(_host.Factory.FilesDirectory, "reports", a.ToString())));
    }

    [Fact]
    [Invariant("INV-189")]
    public async Task Inv189_the_application_role_cannot_rewrite_history()
    {
        var org = await _host.OrganizationAsync();
        foreach (var table in new[] { "finding_event", "risk_decision", "audit_event" })
        {
            await using var scope = await _host.Scopes.OrganizationAsync(org, Ct);
            await using var update = new NpgsqlCommand(
                $"update {table} set organization_id = organization_id where organization_id = @org", scope.Connection, scope.Transaction);
            update.Parameters.AddWithValue("org", org);
            var error = await Assert.ThrowsAsync<PostgresException>(() => update.ExecuteNonQueryAsync(Ct));
            Assert.Equal("42501", error.SqlState);
        }
        // Writing the history itself stays possible: the creation of the organization is audited.
        await using var read = await _host.Scopes.OrganizationAsync(org, Ct);
        Assert.NotEqual(0, await read.Db.AuditEvents.CountAsync(Ct));
    }
}
