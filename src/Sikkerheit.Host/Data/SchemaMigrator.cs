using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Sikkerheit.Host.Data;

/// <summary>
/// Applies the embedded SQL migrations in name order under the schema-owner role. Applied migrations are
/// immutable: a changed script fails the run. Runs only where Database:MigrateOnStart is set (02).
/// </summary>
public sealed class SchemaMigrator(ILogger<SchemaMigrator> logger)
{
    private const long LockKey = 0x5153_4B48_4D49_47; // "SIKKMIG"

    public static IReadOnlyList<(string Name, string Script)> Scripts()
    {
        var assembly = typeof(SchemaMigrator).Assembly;
        const string prefix = "Sikkerheit.Host.Data.Migrations.";
        return assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(prefix, StringComparison.Ordinal) && n.EndsWith(".sql", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .Select(n => (n[prefix.Length..], Read(assembly, n)))
            .ToList();
    }

    public async Task MigrateAsync(string ownerConnectionString, string appRole, CancellationToken ct)
    {
        await using var source = NpgsqlDataSource.Create(ownerConnectionString);
        await MigrateAsync(source, appRole, [], ct);
    }

    /// <param name="principals">
    /// Azure only: managed identities of the slots. They are created as database roles of Entra principals and made
    /// members of the application role, which owns no tables and has no BYPASSRLS (02 «Разделение клиентов»).
    /// </param>
    public async Task MigrateAsync(NpgsqlDataSource owner, string appRole, IReadOnlyList<DatabasePrincipal> principals,
        CancellationToken ct)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(appRole, "^[a-z_][a-z0-9_]{0,62}$"))
        {
            throw new InvalidOperationException("Application role name is not a plain identifier");
        }
        await using var connection = await owner.OpenConnectionAsync(ct);
        await Execute(connection, null, $"select pg_advisory_lock({LockKey})", ct);
        try
        {
            await EnsurePrincipalsAsync(connection, appRole, principals, ct);
            await Execute(connection, null, """
                create table if not exists schema_migrations (
                    name text primary key,
                    sha256 text not null,
                    applied_at timestamptz not null default now())
                """, ct);
            var applied = new Dictionary<string, string>(StringComparer.Ordinal);
            await using (var read = new NpgsqlCommand("select name, sha256 from schema_migrations", connection))
            await using (var reader = await read.ExecuteReaderAsync(ct))
            {
                while (await reader.ReadAsync(ct))
                {
                    applied[reader.GetString(0)] = reader.GetString(1);
                }
            }
            foreach (var (name, script) in Scripts())
            {
                var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(script)));
                if (applied.TryGetValue(name, out var existing))
                {
                    if (existing != hash)
                    {
                        throw new InvalidOperationException($"Applied migration {name} was changed");
                    }
                    continue;
                }
                await using var transaction = await connection.BeginTransactionAsync(ct);
                await Execute(connection, transaction, script.Replace("{{app_role}}", appRole, StringComparison.Ordinal), ct);
                await using (var record = new NpgsqlCommand(
                    "insert into schema_migrations (name, sha256) values (@name, @hash)", connection, transaction))
                {
                    record.Parameters.AddWithValue("name", name);
                    record.Parameters.AddWithValue("hash", hash);
                    await record.ExecuteNonQueryAsync(ct);
                }
                await transaction.CommitAsync(ct);
                logger.LogInformation("Applied migration {Migration}", name);
            }
        }
        finally
        {
            await Execute(connection, null, $"select pg_advisory_unlock({LockKey})", CancellationToken.None);
        }
    }

    private async Task EnsurePrincipalsAsync(NpgsqlConnection connection, string appRole,
        IReadOnlyList<DatabasePrincipal> principals, CancellationToken ct)
    {
        if (principals.Count == 0)
        {
            return;
        }
        await Execute(connection, null, $"""
            do $$ begin
                if not exists (select 1 from pg_roles where rolname = '{appRole}') then
                    create role {appRole} nologin nobypassrls;
                end if;
            end $$
            """, ct);
        foreach (var principal in principals)
        {
            if (!DatabaseConnections.IsPlainRoleName(principal.Name))
            {
                throw new InvalidOperationException("Database principal name is not a plain identifier");
            }
            await using (var exists = new NpgsqlCommand("select 1 from pg_roles where rolname = @name", connection))
            {
                exists.Parameters.AddWithValue("name", principal.Name);
                if (await exists.ExecuteScalarAsync(ct) is null)
                {
                    // Azure Database for PostgreSQL: a role for an Entra service principal by its object id.
                    await using var create = new NpgsqlCommand(
                        "select * from pgaadauth_create_principal_with_oid(@name, @oid, 'service', false, false)", connection);
                    create.Parameters.AddWithValue("name", principal.Name);
                    create.Parameters.AddWithValue("oid", principal.ObjectId.ToString());
                    await create.ExecuteNonQueryAsync(ct);
                    logger.LogInformation("Created database role for managed identity {Principal}", principal.Name);
                }
            }
            await Execute(connection, null, $"grant {appRole} to \"{principal.Name}\"", ct);
        }
    }

    private static async Task Execute(NpgsqlConnection connection, NpgsqlTransaction? transaction, string sql, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        await command.ExecuteNonQueryAsync(ct);
    }

    private static string Read(Assembly assembly, string name)
    {
        using var stream = assembly.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
