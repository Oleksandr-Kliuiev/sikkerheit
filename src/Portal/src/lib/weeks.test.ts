import { describe, expect, it } from 'vitest';
import { query } from '../api/client';
import { formatPercent, isoWeek } from './format';
import { completedWeeks } from './weeks';

describe('report weeks', () => {
  it('are completed ISO weeks with local Monday boundaries', () => {
    // Wednesday 14 October 2026 12:00 in Oslo (UTC+2).
    const weeks = completedWeeks('Europe/Oslo', new Date('2026-10-14T10:00:00Z'), 3);
    expect(weeks[0]).toEqual({ year: 2026, week: 41, periodStart: '2026-10-05T00:00:00+02:00', periodEnd: '2026-10-12T00:00:00+02:00' });
    expect(weeks.map((w) => w.week)).toEqual([41, 40, 39]);
  });

  it('cross the change to winter time and the year', () => {
    const autumn = completedWeeks('Europe/Oslo', new Date('2026-10-27T10:00:00Z'), 1)[0]!;
    expect(autumn).toEqual({ year: 2026, week: 43, periodStart: '2026-10-19T00:00:00+02:00', periodEnd: '2026-10-26T00:00:00+01:00' });
    const newYear = completedWeeks('Europe/Oslo', new Date('2027-01-05T10:00:00Z'), 1)[0]!;
    expect([newYear.year, newYear.week, newYear.periodStart]).toEqual([2026, 53, '2026-12-28T00:00:00+01:00']);
  });

  it('agree with the ISO week of a date', () => {
    expect(isoWeek(new Date(2026, 0, 1))).toEqual({ year: 2026, week: 1 });
    expect(isoWeek(new Date(2027, 0, 3))).toEqual({ year: 2026, week: 53 });
  });
});

describe('helpers', () => {
  it('build filter queries and percentages', () => {
    expect(query({ technicalState: ['open', 'resolved'], severity: [], cursor: null, limit: 50 })).toBe('?technicalState=open%2Cresolved&limit=50');
    expect(formatPercent(0.75, 'en-GB', 'no data')).toBe('75.0%');
    expect(formatPercent(null, 'nb-NO', 'ingen data')).toBe('ingen data');
  });
});
