namespace Sikkerheit.Agent.Collectors.Runtime;

/// <summary>Limits of a collection session (02): 30 seconds per collector, 120 seconds per session.</summary>
public sealed record CollectorLimits(TimeSpan PerCollector, TimeSpan Session)
{
    public static CollectorLimits Default { get; } = new(TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(120));
}

/// <summary>Result of one collector after the run, with the time of the observation.</summary>
public sealed record CollectedItem(ICollector Collector, CollectorOutcome Outcome, DateTimeOffset ObservedAt);

/// <summary>
/// Runs every collector in its own thread (STA where COM is needed). A hung call cannot be interrupted in .NET, so the
/// thread is left running, the check gets unavailable/collector_timeout and <see cref="AbandonedCount"/> grows (02).
/// </summary>
public sealed class CollectorRunner(TimeProvider? time = null)
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private int _abandoned;

    /// <summary>Threads left behind since the start of the service. At <see cref="AbandonedLimit"/> the service stops.</summary>
    public int AbandonedCount => Volatile.Read(ref _abandoned);

    public const int AbandonedLimit = 3;

    public async Task<IReadOnlyList<CollectedItem>> RunAsync(
        IReadOnlyList<ICollector> collectors, CollectionContext context, CollectorLimits limits)
    {
        var started = _time.GetTimestamp();
        var running = collectors.Select(collector => (collector, task: Start(collector, context))).ToList();
        var results = new List<CollectedItem>(running.Count);
        foreach (var (collector, task) in running)
        {
            var elapsed = _time.GetElapsedTime(started);
            var remaining = Min(limits.PerCollector, limits.Session) - elapsed;
            if (remaining < TimeSpan.Zero)
            {
                remaining = TimeSpan.Zero;
            }
            // All collectors start together, so both limits count from the start of the session.
            var finished = await Task.WhenAny(task, Task.Delay(remaining, _time)).ConfigureAwait(false);
            if (finished == task)
            {
                var outcome = await task.ConfigureAwait(false);
                results.Add(new CollectedItem(collector, outcome.Outcome, outcome.At));
                continue;
            }
            Interlocked.Increment(ref _abandoned);
            results.Add(new CollectedItem(collector, CollectorOutcome.Unavailable(ReasonCodes.CollectorTimeout), _time.GetUtcNow()));
        }
        return results;
    }

    private static TimeSpan Min(TimeSpan a, TimeSpan b) => a < b ? a : b;

    private Task<(CollectorOutcome Outcome, DateTimeOffset At)> Start(ICollector collector, CollectionContext context)
    {
        var source = new TaskCompletionSource<(CollectorOutcome, DateTimeOffset)>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            CollectorOutcome outcome;
            try
            {
                outcome = collector.Collect(context);
            }
            catch (Exception exception)
            {
                outcome = CollectorOutcome.Unavailable(CollectorErrors.Reason(exception));
            }
            source.TrySetResult((outcome, _time.GetUtcNow()));
        })
        {
            IsBackground = true,
            Name = "collector-" + collector.CheckId,
        };
        if (collector.RequiresSta && OperatingSystem.IsWindows())
        {
            thread.SetApartmentState(ApartmentState.STA);
        }
        thread.Start();
        return source.Task;
    }
}
