using Npgsql;
using NpgsqlTypes;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.M365;

/// <summary>
/// A short transaction atomically reserves every applicable sliding window. Database time avoids host clock skew.
/// No connection or lock is held while Graph or a delay is awaited; database failure never bypasses the limiter.
/// </summary>
public sealed class PostgresGraphRateStore(DbScopes scopes) : IGraphRateStore
{
    private const long RateLock = 0x534B_4752_4150; // "SKGRAP"; independent of job claims and schema migrations.

    public Task<TimeSpan> TryAcquireAsync(GraphLimit limit, Guid tenant, int requests, CancellationToken ct)
    {
        if (requests < 1 || requests > GraphLimiter.BatchSize(limit))
        {
            throw new ArgumentOutOfRangeException(nameof(requests));
        }
        return ApplyAsync(limit, tenant, requests, null, ct);
    }

    public async Task DeferAsync(GraphLimit limit, Guid tenant, TimeSpan delay, CancellationToken ct)
    {
        if (delay > TimeSpan.Zero)
        {
            await ApplyAsync(limit, tenant, 0, delay, ct);
        }
    }

    private async Task<TimeSpan> ApplyAsync(GraphLimit limit, Guid tenant, int requests, TimeSpan? cooldown,
        CancellationToken ct)
    {
        var rules = GraphRateRule.For(limit, tenant);
        await using var scope = await scopes.PlatformAsync(ct);
        await using (var gate = new NpgsqlCommand("select pg_advisory_xact_lock(@key)", scope.Connection, scope.Transaction))
        {
            gate.Parameters.AddWithValue("key", RateLock);
            await gate.ExecuteNonQueryAsync(ct);
        }
        DateTimeOffset now;
        await using (var time = new NpgsqlCommand("select clock_timestamp()", scope.Connection, scope.Transaction))
        {
            now = (DateTimeOffset)(await time.ExecuteScalarAsync(ct) is DateTime value
                ? new DateTimeOffset(value) : throw new InvalidOperationException("Database clock is unavailable"));
        }
        await using (var purge = new NpgsqlCommand("delete from graph_rate_window where expires_at <= @now", scope.Connection, scope.Transaction))
        {
            purge.Parameters.AddWithValue("now", now);
            await purge.ExecuteNonQueryAsync(ct);
        }
        var states = rules.ToDictionary(r => r.Key, _ => new WindowState(), StringComparer.Ordinal);
        await using (var read = new NpgsqlCommand(
            "select bucket, hits, blocked_until from graph_rate_window where bucket = any(@keys)", scope.Connection, scope.Transaction))
        {
            read.Parameters.AddWithValue("keys", states.Keys.ToArray());
            await using var reader = await read.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                states[reader.GetString(0)] = new WindowState
                {
                    Hits = reader.GetFieldValue<DateTime[]>(1).Select(d => new DateTimeOffset(d)).ToList(),
                    BlockedUntil = reader.GetFieldValue<DateTimeOffset>(2),
                };
            }
        }
        var wait = TimeSpan.Zero;
        foreach (var rule in rules)
        {
            var state = states[rule.Key];
            state.Hits.RemoveAll(hit => hit <= now - rule.Window);
            state.Hits.Sort();
            if (cooldown is { } delay)
            {
                var until = delay > DateTimeOffset.MaxValue - now ? DateTimeOffset.MaxValue : now + delay;
                state.BlockedUntil = until > state.BlockedUntil ? until : state.BlockedUntil;
            }
            var free = state.BlockedUntil;
            if (rule.Capacity > 0 && state.Hits.Count + requests > rule.Capacity)
            {
                // Need enough free places for the entire batch; do not reserve a batch piecemeal.
                var windowFree = state.Hits[state.Hits.Count + requests - rule.Capacity - 1] + rule.Window;
                free = windowFree > free ? windowFree : free;
            }
            wait = free - now > wait ? free - now : wait;
        }
        if (cooldown is not null || wait <= TimeSpan.Zero)
        {
            foreach (var rule in rules)
            {
                var state = states[rule.Key];
                if (cooldown is null && rule.Capacity > 0)
                {
                    state.Hits.AddRange(Enumerable.Repeat(now, requests));
                }
                await using var write = new NpgsqlCommand("""
                    insert into graph_rate_window (bucket, hits, blocked_until, expires_at)
                    values (@key, @hits, @blocked, @expires)
                    on conflict (bucket) do update set hits = excluded.hits,
                        blocked_until = excluded.blocked_until, expires_at = excluded.expires_at
                    """, scope.Connection, scope.Transaction);
                write.Parameters.AddWithValue("key", rule.Key);
                write.Parameters.AddWithValue("hits", NpgsqlDbType.Array | NpgsqlDbType.TimestampTz,
                    state.Hits.Select(h => h.UtcDateTime).ToArray());
                write.Parameters.AddWithValue("blocked", state.BlockedUntil);
                var expiry = now + (rule.Window > TimeSpan.FromMinutes(2) ? rule.Window : TimeSpan.FromMinutes(2));
                write.Parameters.AddWithValue("expires", state.BlockedUntil > expiry ? state.BlockedUntil : expiry);
                await write.ExecuteNonQueryAsync(ct);
            }
        }
        await scope.CommitAsync(ct);
        return wait > TimeSpan.Zero ? wait : TimeSpan.Zero;
    }

    private sealed class WindowState
    {
        public List<DateTimeOffset> Hits { get; init; } = [];
        public DateTimeOffset BlockedUntil { get; set; } = DateTimeOffset.MinValue;
    }
}
