using System.Text;
using System.Text.Json.Nodes;
using Sikkerheit.Agent.Storage;

namespace Sikkerheit.Agent.Tests;

public sealed class BufferTests : IDisposable
{
    private static readonly DateTimeOffset Now = AgentFixture.Start;
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sikkerheit-buffer-" + Guid.NewGuid().ToString("N"));
    private readonly AgentStateStore _state;
    private readonly BatchBuffer _buffer;

    public BufferTests()
    {
        Directory.CreateDirectory(_dir);
        var database = new AgentDatabase(Path.Combine(_dir, "agent.db"));
        _state = new AgentStateStore(database);
        _buffer = new BatchBuffer(database, _state);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static BufferedBatch Batch(long sequence, DateTimeOffset completed, int bytes = 100)
    {
        var padding = new string('x', Math.Max(0, bytes - 120));
        var body = new JsonObject { ["scanId"] = Guid.NewGuid().ToString("D"), ["sequence"] = sequence, ["pad"] = padding };
        return new BufferedBatch(body["scanId"]!.GetValue<string>(), sequence, completed, Encoding.UTF8.GetBytes(body.ToJsonString()), 0);
    }

    [Fact]
    public void Batches_come_from_the_old_to_the_new_and_keep_their_bytes()
    {
        var second = Batch(2, Now);
        var first = Batch(1, Now.AddMinutes(-5));
        _buffer.Enqueue(second, 1_000_000, 7, Now);
        _buffer.Enqueue(first, 1_000_000, 7, Now);

        var oldest = _buffer.Oldest()!;

        Assert.Equal(first.ScanId, oldest.ScanId);
        Assert.Equal(first.Body, oldest.Body);
        Assert.Equal(2, _buffer.Count);
    }

    [Fact]
    public void The_buffer_survives_a_restart_of_the_service()
    {
        _buffer.Enqueue(Batch(1, Now), 1_000_000, 7, Now);

        var reopened = new BatchBuffer(new AgentDatabase(Path.Combine(_dir, "agent.db")), _state);

        Assert.Equal(1, reopened.Count);
        Assert.Equal(1, reopened.NextSequence(0) - 1);
    }

    [Fact]
    public void Overflow_deletes_the_oldest_batches_and_counts_them_in_dropped_batch_count()
    {
        for (var i = 1; i <= 5; i++)
        {
            _buffer.Enqueue(Batch(i, Now.AddMinutes(i), bytes: 400), maxBufferBytes: 1000, 7, Now.AddMinutes(i));
        }

        Assert.True(_buffer.Bytes <= 1000);
        Assert.Equal(5 - _buffer.Count, _buffer.DroppedBatchCount);
        Assert.True(_buffer.DroppedBatchCount >= 2);
        Assert.Equal(5, _buffer.All().Last().Sequence); // the newest is kept
    }

    [Fact]
    public void Batches_older_than_max_buffer_days_are_deleted_and_counted()
    {
        _buffer.Enqueue(Batch(1, Now.AddDays(-7).AddMinutes(-1)), 1_000_000, 7, Now);
        _buffer.Enqueue(Batch(2, Now.AddDays(-6)), 1_000_000, 7, Now);

        Assert.Equal(1, _buffer.Count);
        Assert.Equal(1, _buffer.DroppedBatchCount);
        Assert.Equal(2, _buffer.Oldest()!.Sequence);
    }

    [Fact]
    public void Resequence_deletes_the_batches_accepted_before_the_checkpoint_and_renumbers_the_rest_with_new_scan_ids()
    {
        var a = Batch(5, Now.AddHours(-30));
        var b = Batch(6, Now.AddHours(-20));
        var c = Batch(7, Now.AddHours(-10));
        foreach (var batch in new[] { a, b, c })
        {
            _buffer.Enqueue(batch, 1_000_000, 30, Now);
        }

        var removed = _buffer.Resequence(lastAcceptedSequence: 3, lastAcceptedCompletedAt: Now.AddHours(-20));

        var rest = _buffer.All();
        Assert.Equal(2, removed);
        var only = Assert.Single(rest);
        Assert.Equal(4, only.Sequence);
        Assert.NotEqual(c.ScanId, only.ScanId);
        var body = JsonNode.Parse(only.Body)!;
        Assert.Equal(only.ScanId, body["scanId"]!.GetValue<string>());
        Assert.Equal(4, body["sequence"]!.GetValue<long>());
        Assert.Equal(5, _buffer.NextSequence(3));
        Assert.Equal(0, _buffer.DroppedBatchCount); // accepted earlier, not dropped
    }

    [Fact]
    public void Resequence_without_a_projection_renumbers_all_batches()
    {
        _buffer.Enqueue(Batch(9, Now.AddHours(-3)), 1_000_000, 30, Now);
        _buffer.Enqueue(Batch(10, Now.AddHours(-2)), 1_000_000, 30, Now);

        _buffer.Resequence(0, null);

        Assert.Equal([1L, 2L], _buffer.All().Select(b => b.Sequence).ToArray());
    }

    [Fact]
    public void Sequence_never_goes_below_the_last_accepted_one_and_does_not_repeat_after_the_buffer_is_emptied()
    {
        var batch = Batch(1, Now);
        _buffer.Enqueue(batch, 1_000_000, 7, Now);
        _buffer.Remove(batch.ScanId);

        Assert.Equal(2, _buffer.NextSequence(0));
        Assert.Equal(11, _buffer.NextSequence(10));
    }

    [Fact]
    public void Server_errors_are_counted_per_batch()
    {
        var batch = Batch(1, Now);
        _buffer.Enqueue(batch, 1_000_000, 7, Now);

        Assert.Equal(1, _buffer.RecordServerError(batch.ScanId));
        Assert.Equal(2, _buffer.RecordServerError(batch.ScanId));
    }

    [Fact]
    public void Reject_deletes_and_counts_in_rejected_batch_count()
    {
        var batch = Batch(1, Now);
        _buffer.Enqueue(batch, 1_000_000, 7, Now);

        _buffer.Reject(batch.ScanId);

        Assert.Equal(0, _buffer.Count);
        Assert.Equal(1, _buffer.RejectedBatchCount);
    }
}
