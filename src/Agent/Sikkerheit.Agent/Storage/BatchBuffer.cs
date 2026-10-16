using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;

namespace Sikkerheit.Agent.Storage;

/// <summary>A batch in the buffer: the exact bytes that are sent (a retry sends the same bytes).</summary>
public sealed record BufferedBatch(string ScanId, long Sequence, DateTimeOffset CompletedAt, byte[] Body, int ServerErrors);

/// <summary>
/// Buffer of batches in SQLite (02, 05): by sequence from the old to the new, limited by <c>maxBufferBytes</c> and
/// <c>maxBufferDays</c>; on overflow the oldest are deleted and <c>droppedBatchCount</c> grows.
/// </summary>
public sealed class BatchBuffer(AgentDatabase database, AgentStateStore state)
{
    public long Count => database.InTransaction((c, t) => Scalar(c, t, "SELECT COUNT(*) FROM batch"));

    public long Bytes => database.InTransaction((c, t) => Scalar(c, t, "SELECT COALESCE(SUM(bytes), 0) FROM batch"));

    public long DroppedBatchCount => state.GetLong(StateKeys.DroppedBatchCount);

    public long RejectedBatchCount => state.GetLong(StateKeys.RejectedBatchCount);

    /// <summary>Next sequence number: monotonic over buffer rebuilds, never below the last accepted one.</summary>
    public long NextSequence(long lastAcceptedSequence) =>
        Math.Max(state.GetLong(StateKeys.LastAssignedSequence), lastAcceptedSequence) + 1;

    public void Enqueue(BufferedBatch batch, long maxBufferBytes, int maxBufferDays, DateTimeOffset now)
    {
        database.InTransaction((connection, transaction) =>
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO batch (scan_id, sequence, completed_at, body, bytes) VALUES ($id, $seq, $completed, $body, $bytes)
                """;
            command.Parameters.AddWithValue("$id", batch.ScanId);
            command.Parameters.AddWithValue("$seq", batch.Sequence);
            command.Parameters.AddWithValue("$completed", Format(batch.CompletedAt));
            command.Parameters.AddWithValue("$body", batch.Body);
            command.Parameters.AddWithValue("$bytes", batch.Body.Length);
            command.ExecuteNonQuery();
        });
        state.Set(StateKeys.LastAssignedSequence, batch.Sequence.ToString(CultureInfo.InvariantCulture));
        Trim(maxBufferBytes, maxBufferDays, now);
    }

    /// <summary>Applies the limits: batches older than the days and then the oldest above the size are deleted.</summary>
    public int Trim(long maxBufferBytes, int maxBufferDays, DateTimeOffset now)
    {
        var dropped = 0;
        var cutoff = now - TimeSpan.FromDays(maxBufferDays);
        foreach (var batch in All().Where(b => b.CompletedAt < cutoff))
        {
            Remove(batch.ScanId);
            dropped++;
        }
        while (Bytes > maxBufferBytes && Oldest() is { } oldest)
        {
            Remove(oldest.ScanId);
            dropped++;
        }
        if (dropped > 0)
        {
            state.Increment(StateKeys.DroppedBatchCount, dropped);
        }
        return dropped;
    }

    public BufferedBatch? Oldest() => Query("SELECT scan_id, sequence, completed_at, body, server_errors FROM batch ORDER BY sequence LIMIT 1")
        .FirstOrDefault();

    public IReadOnlyList<BufferedBatch> All() =>
        Query("SELECT scan_id, sequence, completed_at, body, server_errors FROM batch ORDER BY sequence");

    public void Remove(string scanId) => database.InTransaction((connection, transaction) =>
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "DELETE FROM batch WHERE scan_id = $id";
        command.Parameters.AddWithValue("$id", scanId);
        command.ExecuteNonQuery();
    });

    /// <summary>A deleted batch the server rejected: counted in <c>rejectedBatchCount</c> of the check-in.</summary>
    public void Reject(string scanId)
    {
        Remove(scanId);
        state.Increment(StateKeys.RejectedBatchCount);
    }

    /// <summary>Increments the counter of the 500 answers of the batch and returns the new value.</summary>
    public int RecordServerError(string scanId) => database.InTransaction((connection, transaction) =>
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "UPDATE batch SET server_errors = server_errors + 1 WHERE scan_id = $id RETURNING server_errors";
        command.Parameters.AddWithValue("$id", scanId);
        return Convert.ToInt32(command.ExecuteScalar() ?? 0, CultureInfo.InvariantCulture);
    });

    /// <summary>
    /// Resynchronization of the sequence after 409 sequence_conflict (05, "Субъекты и идентичность устройства"): batches with
    /// <c>completedAt</c> not later than the server projection are deleted (they were accepted before the checkpoint), the rest are
    /// renumbered from <c>lastAcceptedSequence + 1</c> with new scanIds. The only exception to the immutability of a batch.
    /// </summary>
    public int Resequence(long lastAcceptedSequence, DateTimeOffset? lastAcceptedCompletedAt)
    {
        var all = All();
        var kept = all.Where(b => lastAcceptedCompletedAt is null || b.CompletedAt > lastAcceptedCompletedAt).ToList();
        var sequence = lastAcceptedSequence;
        database.InTransaction((connection, transaction) =>
        {
            using (var clear = connection.CreateCommand())
            {
                clear.Transaction = transaction;
                clear.CommandText = "DELETE FROM batch";
                clear.ExecuteNonQuery();
            }
            foreach (var batch in kept)
            {
                sequence++;
                var scanId = Guid.NewGuid().ToString("D");
                var body = Rewrite(batch.Body, scanId, sequence);
                using var insert = connection.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = "INSERT INTO batch (scan_id, sequence, completed_at, body, bytes) VALUES ($id, $seq, $completed, $body, $bytes)";
                insert.Parameters.AddWithValue("$id", scanId);
                insert.Parameters.AddWithValue("$seq", sequence);
                insert.Parameters.AddWithValue("$completed", Format(batch.CompletedAt));
                insert.Parameters.AddWithValue("$body", body);
                insert.Parameters.AddWithValue("$bytes", body.Length);
                insert.ExecuteNonQuery();
            }
        });
        state.Set(StateKeys.LastAssignedSequence, sequence.ToString(CultureInfo.InvariantCulture));
        return all.Count - kept.Count;
    }

    public void Clear()
    {
        database.InTransaction((connection, transaction) =>
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "DELETE FROM batch";
            command.ExecuteNonQuery();
        });
    }

    private static byte[] Rewrite(byte[] body, string scanId, long sequence)
    {
        var node = JsonNode.Parse(body)!.AsObject();
        node["scanId"] = scanId;
        node["sequence"] = sequence;
        return Encoding.UTF8.GetBytes(node.ToJsonString(new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
    }

    private List<BufferedBatch> Query(string sql) => database.InTransaction((connection, transaction) =>
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        using var reader = command.ExecuteReader();
        var rows = new List<BufferedBatch>();
        while (reader.Read())
        {
            rows.Add(new BufferedBatch(
                reader.GetString(0), reader.GetInt64(1),
                DateTimeOffset.Parse(reader.GetString(2), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal),
                (byte[])reader["body"], reader.GetInt32(4)));
        }
        return rows;
    });

    private static long Scalar(SqliteConnection connection, SqliteTransaction transaction, string sql)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static string Format(DateTimeOffset value) => value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
}
