using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sikkerheit.Host.Data;
using Testcontainers.PostgreSql;

[assembly: AssemblyFixture(typeof(Sikkerheit.IntegrationTests.Infrastructure.PostgresFixture))]

namespace Sikkerheit.IntegrationTests.Infrastructure;

/// <summary>
/// One PostgreSQL 17 container per test run. Roles mirror production: the owner applies migrations,
/// the application role has no BYPASSRLS and owns nothing (02 «Разделение клиентов»). Every service instance of a test
/// gets its own database copied from a migrated template, so job runners and clocks of parallel tests never meet.
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    public const string AppRole = "sikkerheit_app";
    private const string OwnerRole = "sikkerheit_owner";
    private const string Database = "sikkerheit";
    private const string Template = "sikkerheit_template";
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:17-alpine").Build();
    private readonly SemaphoreSlim _create = new(1, 1);
    private string _admin = "";

    public string OwnerConnectionString { get; private set; } = "";
    public string AppConnectionString { get; private set; } = "";
    public NpgsqlDataSource AppDataSource { get; private set; } = null!;

    public async ValueTask InitializeAsync()
    {
        await _container.StartAsync();
        var admin = new NpgsqlConnectionStringBuilder(_container.GetConnectionString());
        await using (var connection = new NpgsqlConnection(admin.ConnectionString))
        {
            await connection.OpenAsync();
            foreach (var sql in new[]
                     {
                         $"create role {OwnerRole} login password 'owner-test'",
                         $"create role {AppRole} login password 'app-test' nobypassrls",
                         $"create database {Database} owner {OwnerRole}",
                     })
            {
                await using var command = new NpgsqlCommand(sql, connection);
                await command.ExecuteNonQueryAsync();
            }
        }
        OwnerConnectionString = new NpgsqlConnectionStringBuilder(admin.ConnectionString)
        {
            Database = Database, Username = OwnerRole, Password = "owner-test",
        }.ConnectionString;
        AppConnectionString = new NpgsqlConnectionStringBuilder(admin.ConnectionString)
        {
            Database = Database, Username = AppRole, Password = "app-test",
        }.ConnectionString;
        await new SchemaMigrator(NullLogger<SchemaMigrator>.Instance).MigrateAsync(OwnerConnectionString, AppRole, default);
        AppDataSource = NpgsqlDataSource.Create(AppConnectionString);

        // The template is migrated over a non-pooled connection: no session may stay open on a template database.
        _admin = new NpgsqlConnectionStringBuilder(admin.ConnectionString) { Pooling = false }.ConnectionString;
        await ExecuteAsync($"create database {Template} owner {OwnerRole}");
        await new SchemaMigrator(NullLogger<SchemaMigrator>.Instance).MigrateAsync(
            new NpgsqlConnectionStringBuilder(OwnerConnectionString) { Database = Template, Pooling = false }.ConnectionString,
            AppRole, default);
    }

    /// <summary>A new migrated database for one service instance; returns the connection string of the app role.</summary>
    public async Task<string> CreateDatabaseAsync()
    {
        var name = "sikkerheit_" + Guid.NewGuid().ToString("N")[..16];
        await _create.WaitAsync();
        try
        {
            await ExecuteAsync($"create database {name} template {Template} owner {OwnerRole}");
        }
        finally
        {
            _create.Release();
        }
        return new NpgsqlConnectionStringBuilder(AppConnectionString) { Database = name }.ConnectionString;
    }

    /// <summary>
    /// A copy of a database at this moment — the stand-in for a point-in-time restore. Sessions still open on the source
    /// are ended first (a template database must have none). Returns the app role connection string of the copy.
    /// </summary>
    public async Task<string> CloneDatabaseAsync(string appConnectionString)
    {
        var source = new NpgsqlConnectionStringBuilder(appConnectionString).Database!;
        var name = "sikkerheit_" + Guid.NewGuid().ToString("N")[..16];
        await _create.WaitAsync();
        try
        {
            await ExecuteAsync($"select pg_terminate_backend(pid) from pg_stat_activity where datname = '{source}' and pid <> pg_backend_pid()");
            await ExecuteAsync($"create database {name} template {source} owner {OwnerRole}");
        }
        finally
        {
            _create.Release();
        }
        return new NpgsqlConnectionStringBuilder(AppConnectionString) { Database = name }.ConnectionString;
    }

    private async Task ExecuteAsync(string sql)
    {
        await using var connection = new NpgsqlConnection(_admin);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }

    public async ValueTask DisposeAsync()
    {
        if (AppDataSource is not null)
        {
            await AppDataSource.DisposeAsync();
        }
        await _container.DisposeAsync();
    }
}
