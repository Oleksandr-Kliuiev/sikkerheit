using System.Text;
using Npgsql;

namespace Sikkerheit.Host.Data;

/// <summary>Receives the rows of one client table of the organization as JSON Lines (the export of 05).</summary>
public delegate Task TableRowsWriter(string table, byte[] jsonLines, int rows);

/// <summary>
/// Operations on every row of the scope's organization in the client tables a module names: deletion and the export as
/// JSON Lines. A module passes only its own tables (02 «Структура репозитория»); the caller keeps the order of the
/// foreign keys.
/// </summary>
public static class OrganizationRows
{
    /// <summary>Deletes the rows of the scope's organization from the tables, in the given order.</summary>
    public static async Task DeleteAsync(DbScope scope, IReadOnlyList<string> tables, CancellationToken ct)
    {
        foreach (var table in tables)
        {
            await using var delete = new NpgsqlCommand($"delete from {table} where {KeyColumn(table)} = @org",
                scope.Connection, scope.Transaction);
            delete.Parameters.AddWithValue("org", scope.OrganizationId!.Value);
            await delete.ExecuteNonQueryAsync(ct);
        }
    }

    /// <summary>
    /// Writes the rows of the scope's organization from every table in its stable order, from the snapshot of the scope's
    /// transaction: one JSON object per row with the database column names.
    /// </summary>
    public static async Task ExportAsync(DbScope scope, IReadOnlyList<(string Table, string Order)> tables,
        TableRowsWriter write, CancellationToken ct)
    {
        foreach (var (table, order) in tables)
        {
            await using var command = new NpgsqlCommand(
                $"select to_jsonb(t)::text from {table} t where t.{KeyColumn(table)} = @org order by {order}",
                scope.Connection, scope.Transaction);
            command.Parameters.AddWithValue("org", scope.OrganizationId!.Value);
            using var lines = new MemoryStream();
            var count = 0;
            await using (var reader = await command.ExecuteReaderAsync(ct))
            {
                while (await reader.ReadAsync(ct))
                {
                    lines.Write(Encoding.UTF8.GetBytes(reader.GetString(0)));
                    lines.WriteByte((byte)'\n');
                    count++;
                }
            }
            await write(table, lines.ToArray(), count);
        }
    }

    private static string KeyColumn(string table) => table == "organization" ? "id" : "organization_id";
}
