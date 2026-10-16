/**
 * Completed ISO weeks of an organization's time zone for createReport: Monday 00:00 to Monday 00:00 local time,
 * sent with the local offset (05 «Отчёт и покрытие»).
 */
export interface ReportWeek {
  year: number;
  week: number;
  periodStart: string;
  periodEnd: string;
}

function offsetMinutes(timeZone: string, instant: Date): number {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
  }).formatToParts(instant);
  const value = (type: string) => Number(parts.find((p) => p.type === type)?.value);
  const asUtc = Date.UTC(value('year'), value('month') - 1, value('day'), value('hour'), value('minute'), value('second'));
  return Math.round((asUtc - instant.getTime()) / 60_000);
}

/** The instant of a local wall time in the zone (two passes settle the offset around daylight saving changes). */
export function zonedInstant(timeZone: string, year: number, month: number, day: number): Date {
  const guess = Date.UTC(year, month - 1, day);
  let instant = new Date(guess - offsetMinutes(timeZone, new Date(guess)) * 60_000);
  instant = new Date(guess - offsetMinutes(timeZone, instant) * 60_000);
  return instant;
}

function formatWithOffset(timeZone: string, instant: Date): string {
  const offset = offsetMinutes(timeZone, instant);
  const local = new Date(instant.getTime() + offset * 60_000);
  const pad = (n: number) => String(Math.abs(n)).padStart(2, '0');
  const sign = offset >= 0 ? '+' : '-';
  return `${local.getUTCFullYear()}-${pad(local.getUTCMonth() + 1)}-${pad(local.getUTCDate())}T00:00:00${sign}${pad(Math.trunc(offset / 60))}:${pad(offset % 60)}`;
}

/** The last completed weeks before now, newest first. */
export function completedWeeks(timeZone: string, now: Date, count: number): ReportWeek[] {
  const offset = offsetMinutes(timeZone, now);
  const local = new Date(now.getTime() + offset * 60_000);
  const weekday = local.getUTCDay() || 7;
  let monday = new Date(Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate() - (weekday - 1)));
  const weeks: ReportWeek[] = [];
  for (let i = 0; i < count; i++) {
    const previous = new Date(monday.getTime() - 7 * 86_400_000);
    const start = zonedInstant(timeZone, previous.getUTCFullYear(), previous.getUTCMonth() + 1, previous.getUTCDate());
    const end = zonedInstant(timeZone, monday.getUTCFullYear(), monday.getUTCMonth() + 1, monday.getUTCDate());
    const thursday = new Date(previous.getTime() + 3 * 86_400_000);
    const yearStart = Date.UTC(thursday.getUTCFullYear(), 0, 1);
    weeks.push({
      year: thursday.getUTCFullYear(),
      week: Math.ceil(((thursday.getTime() - yearStart) / 86_400_000 + 1) / 7),
      periodStart: formatWithOffset(timeZone, start),
      periodEnd: formatWithOffset(timeZone, end),
    });
    monday = previous;
  }
  return weeks;
}
