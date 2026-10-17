using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Organizations;

public static class PolicyTemplateStore
{
    private const string Columns = "v.template_id, v.revision, v.name, v.description, v.content::text, v.archived, v.created_at, v.created_by";

    public static async Task<PolicyTemplateDto> GetAsync(DbScope scope, Guid id, bool shareLock, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand($"""
            select {Columns} from policy_template t
            join policy_template_revision v on v.template_id = t.id and v.revision = t.current_revision
            where t.id = @id
            """ + (shareLock ? " for share of t" : ""), scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) throw new ApiProblemException(ProblemCodes.NotFound);
        return Read(reader);
    }

    public static async Task<List<PolicyTemplateDto>> ListAsync(DbScope scope, Guid? id, bool includeArchived,
        Guid? beforeId, int? beforeRevision, int take, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand($"""
            select {Columns} from policy_template_revision v
            join policy_template t on t.id = v.template_id
            where (@id::uuid is not null and v.template_id = @id and (@rev::int is null or v.revision < @rev))
               or (@id::uuid is null and v.revision = t.current_revision and (@archived or not v.archived)
                   and (@before::uuid is null or v.template_id < @before))
            order by v.template_id desc, v.revision desc limit @take
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("id", NpgsqlDbType.Uuid, (object?)id ?? DBNull.Value);
        command.Parameters.AddWithValue("rev", NpgsqlDbType.Integer, (object?)beforeRevision ?? DBNull.Value);
        command.Parameters.AddWithValue("before", NpgsqlDbType.Uuid, (object?)beforeId ?? DBNull.Value);
        command.Parameters.AddWithValue("archived", includeArchived);
        command.Parameters.AddWithValue("take", take);
        var rows = new List<PolicyTemplateDto>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) rows.Add(Read(reader));
        return rows;
    }

    public static async Task<PolicyTemplateDto> SaveAsync(DbScope scope, Guid? existing, string? ifMatch,
        string name, string description, JsonElement content, bool archived, Guid actor, DateTimeOffset now, CancellationToken ct)
    {
        var id = existing ?? Guid.CreateVersion7();
        var revision = 1;
        if (existing is not null)
        {
            await using var current = new NpgsqlCommand("select current_revision from policy_template where id = @id for update", scope.Connection, scope.Transaction);
            current.Parameters.AddWithValue("id", id);
            var value = await current.ExecuteScalarAsync(ct) ?? throw new ApiProblemException(ProblemCodes.NotFound);
            RequireVersion(ifMatch, (int)value);
            revision = (int)value + 1;
        }
        await using (var head = new NpgsqlCommand(existing is null
            ? "insert into policy_template (id, current_revision) values (@id, @revision)"
            : "update policy_template set current_revision = @revision where id = @id", scope.Connection, scope.Transaction))
        {
            head.Parameters.AddWithValue("id", id);
            head.Parameters.AddWithValue("revision", revision);
            await head.ExecuteNonQueryAsync(ct);
        }
        await using var insert = new NpgsqlCommand("""
            insert into policy_template_revision (template_id, revision, name, description, content, archived, created_at, created_by)
            values (@id, @revision, @name, @description, @content, @archived, @now, @actor)
            """, scope.Connection, scope.Transaction);
        insert.Parameters.AddWithValue("id", id);
        insert.Parameters.AddWithValue("revision", revision);
        insert.Parameters.AddWithValue("name", name);
        insert.Parameters.AddWithValue("description", description);
        insert.Parameters.AddWithValue("content", NpgsqlDbType.Jsonb, content.GetRawText());
        insert.Parameters.AddWithValue("archived", archived);
        insert.Parameters.AddWithValue("now", now);
        insert.Parameters.AddWithValue("actor", actor);
        await insert.ExecuteNonQueryAsync(ct);
        return new(id, revision, name, description, content, archived, now, actor);
    }

    public static void RequireVersion(string? ifMatch, int revision)
    {
        if (string.IsNullOrEmpty(ifMatch)) throw new ApiProblemException(ProblemCodes.IfMatchRequired);
        if (ifMatch != $"\"{revision}\"") throw new ApiProblemException(ProblemCodes.RevisionMismatch);
    }

    private static PolicyTemplateDto Read(NpgsqlDataReader reader) => new(reader.GetGuid(0), reader.GetInt32(1),
        reader.GetString(2), reader.GetString(3), JsonDocument.Parse(reader.GetString(4)).RootElement.Clone(),
        reader.GetBoolean(5), reader.GetFieldValue<DateTimeOffset>(6), reader.GetGuid(7));
}
