namespace Sikkerheit.Host.M365;

public enum GraphLimit
{
    Default,
    AuthMethods,
    ConditionalAccess,
    SignInActivity,
}

/// <summary>Atomic quota reservations and server cooldowns, shared by all service instances.</summary>
public interface IGraphRateStore
{
    Task<TimeSpan> TryAcquireAsync(GraphLimit limit, Guid tenant, int requests, CancellationToken ct);
    Task DeferAsync(GraphLimit limit, Guid tenant, TimeSpan delay, CancellationToken ct);
}

internal sealed record GraphRateRule(string Key, int Capacity, TimeSpan Window)
{
    public static IReadOnlyList<GraphRateRule> For(GraphLimit limit, Guid tenant)
    {
        var rules = new List<GraphRateRule> { new($"tenant:{tenant:N}", 0, TimeSpan.Zero) };
        rules.AddRange(limit switch
        {
            GraphLimit.AuthMethods => [new($"am:{tenant:N}", 5, TimeSpan.FromSeconds(10)), new("am:all", 122, TimeSpan.FromSeconds(10))],
            GraphLimit.ConditionalAccess => [new($"ca:{tenant:N}", 1, TimeSpan.FromSeconds(1))],
            GraphLimit.SignInActivity => [new("si:all", 10, TimeSpan.FromMinutes(1))],
            _ => Array.Empty<GraphRateRule>(),
        });
        return rules;
    }
}

public sealed class GraphLimiter(IGraphRateStore store, TimeProvider clock)
{
    // A batch is sent at once, so it must fit inside every applicable window at once.
    public static int BatchSize(GraphLimit limit) => limit switch
    {
        GraphLimit.AuthMethods => 5,
        GraphLimit.ConditionalAccess => 1,
        GraphLimit.SignInActivity => 10,
        _ => 20,
    };

    public async Task WaitAsync(GraphLimit limit, Guid tenant, int requests, CancellationToken ct)
    {
        if (requests < 1 || requests > BatchSize(limit))
        {
            throw new ArgumentOutOfRangeException(nameof(requests), "Reserve only requests that can be sent in one batch");
        }
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var wait = await store.TryAcquireAsync(limit, tenant, requests, ct);
            if (wait <= TimeSpan.Zero)
            {
                return;
            }
            GraphMetrics.Wait(limit, wait);
            // Task.Delay has an upper bound. Keep very long Retry-After cancellable by the collection deadline.
            await Task.Delay(wait > TimeSpan.FromDays(1) ? TimeSpan.FromDays(1) : wait, clock, ct);
        }
    }

    public Task DeferAsync(GraphLimit limit, Guid tenant, TimeSpan delay, CancellationToken ct) =>
        delay > TimeSpan.Zero ? store.DeferAsync(limit, tenant, delay, ct) : Task.CompletedTask;
}
