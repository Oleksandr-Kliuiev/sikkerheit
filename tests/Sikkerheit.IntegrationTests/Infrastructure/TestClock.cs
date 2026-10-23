namespace Sikkerheit.IntegrationTests.Infrastructure;

/// <summary>
/// System time shifted by an offset: tests move «now» to a chosen moment while timers and delays keep running in real
/// time (Graph limiter and retries do not hang).
/// </summary>
public sealed class TestClock : TimeProvider
{
    private long _offsetTicks;
    private long _frozenTicks;

    /// <summary>
    /// A flowing clock reads at microsecond precision, the precision of the contract (at most six fractional digits) and of
    /// PostgreSQL. The system clock of Linux has 100 ns, so tests that put «now» into request bodies would send
    /// values the contract rejects there while passing on macOS. A frozen clock keeps its exact ticks.
    /// </summary>
    public override DateTimeOffset GetUtcNow()
    {
        if (Interlocked.Read(ref _frozenTicks) is var ticks && ticks != 0)
        {
            return new DateTimeOffset(ticks, TimeSpan.Zero);
        }
        var moment = base.GetUtcNow().AddTicks(Interlocked.Read(ref _offsetTicks));
        return moment.AddTicks(-(moment.Ticks % 10));
    }

    /// <summary>Freeze the clock for exact due-date boundary tests; timers still use real time.</summary>
    public void Freeze(DateTimeOffset moment) => Interlocked.Exchange(ref _frozenTicks, moment.UtcTicks);

    /// <summary>Moves «now» to the moment; time keeps flowing from there.</summary>
    public void Set(DateTimeOffset moment)
    {
        Interlocked.Exchange(ref _offsetTicks, (moment - base.GetUtcNow()).Ticks);
        Interlocked.Exchange(ref _frozenTicks, 0);
    }

    /// <summary>Local time in a zone as an instant, for readable test scenarios.</summary>
    public void SetLocal(string timezone, int year, int month, int day, int hour, int minute = 0)
    {
        var zone = TimeZoneInfo.FindSystemTimeZoneById(timezone);
        var local = new DateTime(year, month, day, hour, minute, 0, DateTimeKind.Unspecified);
        Set(new DateTimeOffset(local, zone.GetUtcOffset(local)));
    }
}
