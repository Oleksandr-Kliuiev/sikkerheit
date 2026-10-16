using System.Data;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Sikkerheit.Host.Data;

/// <summary>
/// An open connection, a transaction whose first statement sets the request scope (02 «Разделение клиентов»)
/// and an EF Core context bound to them. Dispose without Commit rolls back.
/// </summary>
public sealed class DbScope : IAsyncDisposable
{
    private readonly NpgsqlConnection _connection;
    private bool _completed;

    internal DbScope(NpgsqlConnection connection, NpgsqlTransaction transaction, SikkerheitDb db, Guid? organizationId)
    {
        _connection = connection;
        Transaction = transaction;
        Db = db;
        OrganizationId = organizationId;
    }

    public SikkerheitDb Db { get; }
    public NpgsqlTransaction Transaction { get; }
    public NpgsqlConnection Connection => _connection;
    public Guid? OrganizationId { get; }

    public async Task CommitAsync(CancellationToken ct)
    {
        await Db.SaveChangesAsync(ct);
        await Transaction.CommitAsync(ct);
        _completed = true;
    }

    public async ValueTask DisposeAsync()
    {
        if (!_completed)
        {
            try
            {
                await Transaction.RollbackAsync();
            }
            catch (InvalidOperationException)
            {
                // The transaction already completed or the connection is broken.
            }
        }
        await Db.DisposeAsync();
        await Transaction.DisposeAsync();
        await _connection.DisposeAsync();
    }
}

/// <summary>Creates scoped database sessions. The only place that sets the RLS scope.</summary>
public sealed class DbScopes(NpgsqlDataSource dataSource)
{
    /// <summary>Organization scope: reads and writes only rows of one organization.</summary>
    public Task<DbScope> OrganizationAsync(Guid organizationId, CancellationToken ct) =>
        OpenAsync(organizationId, readOnlyAll: false, ct);

    /// <summary>Organization scope over one consistent snapshot of all tables (REPEATABLE READ), for exports.</summary>
    public Task<DbScope> OrganizationSnapshotAsync(Guid organizationId, CancellationToken ct) =>
        OpenAsync(organizationId, readOnlyAll: false, ct, IsolationLevel.RepeatableRead);

    /// <summary>Read-all scope for the closed list of components in 02; the transaction is READ ONLY.</summary>
    public Task<DbScope> ReadAllAsync(CancellationToken ct) => OpenAsync(null, readOnlyAll: true, ct);

    /// <summary>No client scope: platform tables only (staff, sessions, jobs, tombstones).</summary>
    public Task<DbScope> PlatformAsync(CancellationToken ct) => OpenAsync(null, readOnlyAll: false, ct);

    private async Task<DbScope> OpenAsync(Guid? organizationId, bool readOnlyAll, CancellationToken ct,
        IsolationLevel isolation = IsolationLevel.ReadCommitted)
    {
        var connection = await dataSource.OpenConnectionAsync(ct);
        try
        {
            var transaction = await connection.BeginTransactionAsync(isolation, ct);
            if (readOnlyAll)
            {
                await using var readOnly = new NpgsqlCommand("set transaction read only", connection, transaction);
                await readOnly.ExecuteNonQueryAsync(ct);
                await using var all = new NpgsqlCommand("select app.set_scope_all()", connection, transaction);
                await all.ExecuteNonQueryAsync(ct);
            }
            else if (organizationId is { } org)
            {
                await using var scope = new NpgsqlCommand("select app.set_scope(@org)", connection, transaction);
                scope.Parameters.AddWithValue("org", org);
                await scope.ExecuteNonQueryAsync(ct);
            }
            var options = new DbContextOptionsBuilder<SikkerheitDb>().UseNpgsql(connection).Options;
            var db = new SikkerheitDb(options);
            await db.Database.UseTransactionAsync(transaction, ct);
            return new DbScope(connection, transaction, db, organizationId);
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }
}
