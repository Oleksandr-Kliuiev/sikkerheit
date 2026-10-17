namespace Sikkerheit.UnitTests.M365;

/// <summary>Deterministic timers: long server delays can be tested without real sleeps or extra dependencies.</summary>
internal sealed class ManualClock : TimeProvider
{
    private readonly object _gate = new();
    private readonly List<Timer> _timers = [];
    private long _ticks;
    private static readonly DateTimeOffset Epoch = new(2026, 10, 17, 12, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() { lock (_gate) { return Epoch.AddTicks(_ticks); } }
    public override long GetTimestamp() { lock (_gate) { return _ticks; } }
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    public int Pending { get { lock (_gate) { return _timers.Count(t => t.Due != long.MaxValue); } } }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new Timer(this, callback, state);
        lock (_gate)
        {
            _timers.Add(timer);
            timer.Change(dueTime, period);
        }
        return timer;
    }

    public void Advance(TimeSpan amount)
    {
        List<Timer> due;
        lock (_gate)
        {
            _ticks += amount.Ticks;
            due = _timers.Where(t => t.Due <= _ticks).ToList();
            foreach (var timer in due)
            {
                timer.Due = timer.Period == long.MaxValue ? long.MaxValue : _ticks + timer.Period;
            }
        }
        foreach (var timer in due)
        {
            timer.Callback(timer.State);
        }
    }

    private sealed class Timer(ManualClock clock, TimerCallback callback, object? state) : ITimer
    {
        public TimerCallback Callback { get; } = callback;
        public object? State { get; } = state;
        public long Due { get; set; } = long.MaxValue;
        public long Period { get; private set; } = long.MaxValue;

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            lock (clock._gate)
            {
                Due = dueTime == Timeout.InfiniteTimeSpan ? long.MaxValue : clock._ticks + dueTime.Ticks;
                Period = period == Timeout.InfiniteTimeSpan ? long.MaxValue : period.Ticks;
                return true;
            }
        }

        public void Dispose() { lock (clock._gate) { clock._timers.Remove(this); } }
        public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
    }
}
