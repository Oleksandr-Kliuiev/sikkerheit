using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Host.Data;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.IntegrationTests;

/// <summary>AT-01, database part: scope, RLS and pool reset.</summary>
public sealed class RowLevelSecurityTests(PostgresFixture postgres)
{
    private readonly DbScopes _scopes = new(postgres.AppDataSource);
    private readonly CancellationToken _ct = TestContext.Current.CancellationToken;

    private async Task<Guid> CreateOrganization()
    {
        var id = Guid.NewGuid();
        await using var scope = await _scopes.OrganizationAsync(id, _ct);
        scope.Db.Organizations.Add(new Organization
        {
            Id = id, Name = "Org " + id.ToString("N")[..6], Timezone = "Europe/Oslo", ReportLanguage = "nb",
            Status = "active", CreatedAt = DateTimeOffset.UtcNow,
        });
        await scope.CommitAsync(_ct);
        return id;
    }

    [Fact]
    public async Task Query_without_scope_returns_no_client_rows()
    {
        await CreateOrganization();
        await using var scope = await _scopes.PlatformAsync(_ct);
        Assert.Equal(0, await scope.Db.Organizations.CountAsync(_ct));
    }

    [Fact]
    public async Task Organization_scope_sees_only_its_rows()
    {
        var a = await CreateOrganization();
        var b = await CreateOrganization();
        await using var scope = await _scopes.OrganizationAsync(a, _ct);
        var visible = await scope.Db.Organizations.Select(o => o.Id).ToListAsync(_ct);
        Assert.Equal([a], visible);
        Assert.DoesNotContain(b, visible);
    }

    [Fact]
    public async Task Insert_into_another_organization_is_rejected()
    {
        var a = await CreateOrganization();
        var b = await CreateOrganization();
        await using var scope = await _scopes.OrganizationAsync(a, _ct);
        scope.Db.AuditEvents.Add(new AuditEvent
        {
            OrganizationId = b, Id = Guid.NewGuid(), OccurredAt = DateTimeOffset.UtcNow, ActorType = "system",
            Action = "test.write", TargetType = "organization", TargetId = b.ToString(), CorrelationId = "t",
        });
        var error = await Assert.ThrowsAsync<DbUpdateException>(() => scope.Db.SaveChangesAsync(_ct));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, ((PostgresException)error.InnerException!).SqlState);
    }

    [Fact]
    public async Task Update_and_delete_in_another_organization_touch_no_rows()
    {
        var a = await CreateOrganization();
        var b = await CreateOrganization();
        await using var scope = await _scopes.OrganizationAsync(a, _ct);
        var updated = await scope.Db.Database.ExecuteSqlInterpolatedAsync(
            $"update organization set name = 'taken' where id = {b}", _ct);
        var deleted = await scope.Db.Database.ExecuteSqlInterpolatedAsync(
            $"delete from organization where id = {b}", _ct);
        Assert.Equal(0, updated);
        Assert.Equal(0, deleted);
    }

    [Fact]
    public async Task Read_all_scope_sees_every_organization_and_cannot_write()
    {
        var a = await CreateOrganization();
        var b = await CreateOrganization();
        await using var scope = await _scopes.ReadAllAsync(_ct);
        var visible = await scope.Db.Organizations.Select(o => o.Id).ToListAsync(_ct);
        Assert.Contains(a, visible);
        Assert.Contains(b, visible);
        var error = await Assert.ThrowsAsync<PostgresException>(() =>
            scope.Db.Database.ExecuteSqlInterpolatedAsync($"update organization set name = 'x' where id = {a}", _ct));
        Assert.Equal(PostgresErrorCodes.ReadOnlySqlTransaction, error.SqlState);
    }

    [Fact]
    public async Task Read_all_scope_requires_a_read_only_transaction()
    {
        await using var connection = await postgres.AppDataSource.OpenConnectionAsync(_ct);
        await using var transaction = await connection.BeginTransactionAsync(_ct);
        await using var command = new NpgsqlCommand("select app.set_scope_all()", connection, transaction);
        await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(_ct));
    }

    [Fact]
    public async Task Scope_does_not_survive_the_transaction_on_a_pooled_connection()
    {
        var a = await CreateOrganization();
        await using (var scope = await _scopes.OrganizationAsync(a, _ct))
        {
            Assert.Equal(1, await scope.Db.Organizations.CountAsync(_ct));
            await scope.CommitAsync(_ct);
        }
        await using var next = await _scopes.PlatformAsync(_ct);
        Assert.Equal(0, await next.Db.Organizations.CountAsync(_ct));
    }

    [Fact]
    public async Task Application_role_cannot_bypass_row_security()
    {
        await using var connection = await postgres.AppDataSource.OpenConnectionAsync(_ct);
        await using var command = new NpgsqlCommand(
            "select rolbypassrls, rolsuper from pg_roles where rolname = current_user", connection);
        await using var reader = await command.ExecuteReaderAsync(_ct);
        Assert.True(await reader.ReadAsync(_ct));
        Assert.False(reader.GetBoolean(0));
        Assert.False(reader.GetBoolean(1));
    }

    [Fact]
    public async Task Tenant_owner_lookup_finds_an_active_tenant_without_scope()
    {
        var a = await CreateOrganization();
        var tenant = Guid.NewGuid();
        await using (var scope = await _scopes.OrganizationAsync(a, _ct))
        {
            scope.Db.TenantConnections.Add(new TenantConnection
            {
                OrganizationId = a, Status = "active", EntraTenantId = tenant, ConnectedAt = DateTimeOffset.UtcNow,
            });
            await scope.CommitAsync(_ct);
        }
        await using var platform = await _scopes.PlatformAsync(_ct);
        var owner = await platform.Db.Database
            .SqlQuery<Guid?>($"select app.active_tenant_owner({tenant}) as \"Value\"").SingleAsync(_ct);
        Assert.Equal(a, owner);
        Assert.Equal(0, await platform.Db.TenantConnections.CountAsync(_ct));
    }
}
