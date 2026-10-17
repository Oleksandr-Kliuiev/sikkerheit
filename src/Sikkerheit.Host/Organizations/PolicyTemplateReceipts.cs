using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Organizations;

public static class PolicyTemplateReceipts
{
    public static async Task<PolicyTemplateApplication?> ReadAsync(DbScope scope, string tokenHash, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select template_id, template_revision, policy_version, applied_at from policy_template_application
            where organization_id = @org and token_hash = @hash
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", scope.OrganizationId!.Value);
        command.Parameters.AddWithValue("hash", tokenHash);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? new(reader.GetGuid(0), reader.GetInt32(1), reader.GetInt32(2),
            reader.GetFieldValue<DateTimeOffset>(3), true) : null;
    }

    public static async Task InsertAsync(DbScope scope, string tokenHash, Guid actor, PolicyTemplateApplication result, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            insert into policy_template_application
                (organization_id, token_hash, template_id, template_revision, policy_version, applied_at, applied_by)
            values (@org, @hash, @template, @revision, @policy, @at, @actor)
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", scope.OrganizationId!.Value);
        command.Parameters.AddWithValue("hash", tokenHash);
        command.Parameters.AddWithValue("template", result.TemplateId);
        command.Parameters.AddWithValue("revision", result.TemplateRevision);
        command.Parameters.AddWithValue("policy", result.PolicyVersion);
        command.Parameters.AddWithValue("at", result.AppliedAt);
        command.Parameters.AddWithValue("actor", actor);
        await command.ExecuteNonQueryAsync(ct);
    }
}
