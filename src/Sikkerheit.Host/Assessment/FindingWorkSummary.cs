using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Assessment;

public sealed record OverdueWorkCount(Guid OrganizationId, long Count);

/// <summary>Work deadlines, not a security verdict. Risk decisions and retired subjects are excluded.</summary>
public static class FindingWorkSummary
{
    public static async Task<IReadOnlyList<OverdueWorkCount>> OverdueAsync(DbScope scope, DateTimeOffset now, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select f.organization_id, count(*) from finding f
            join subject s on s.organization_id = f.organization_id and s.id = f.subject_id
            where f.technical_state = 'open' and f.workflow_state in ('new', 'in_progress')
              and f.due_at < @now and s.retired_at is null
            group by f.organization_id
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("now", now);
        var counts = new List<OverdueWorkCount>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) { counts.Add(new(reader.GetGuid(0), reader.GetInt64(1))); }
        return counts;
    }
}
