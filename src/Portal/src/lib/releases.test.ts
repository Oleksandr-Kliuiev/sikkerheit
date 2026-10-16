import { describe, expect, it } from 'vitest';
import { currentSecurityMonth, parseEntries } from './releases';

describe('parseEntries', () => {
  it('reads one entry per line with the month, date and the way it is offered', () => {
    const { entries, invalid } = parseEntries('26200 9711 5062002 security_monthly 2026-10 2026-10-13\n\n# comment\n26100 8390 5060002 hotpatch 2026-05 2026-05-13 manual');
    expect(invalid).toEqual([]);
    expect(entries).toEqual([
      { branchBuild: 26200, ubr: 9711, kb: '5062002', kind: 'security_monthly', securityMonth: '2026-10', releaseAt: '2026-10-13T00:00:00.000Z', autoOffered: true },
      { branchBuild: 26100, ubr: 8390, kb: '5060002', kind: 'hotpatch', securityMonth: '2026-05', releaseAt: '2026-05-13T00:00:00.000Z', autoOffered: false },
    ]);
  });

  it('accepts a release without security fixes and a missing date', () => {
    const { entries, invalid } = parseEntries('26200 9712 5062003 preview -');
    expect(invalid).toEqual([]);
    expect(entries[0]).toMatchObject({ securityMonth: null, kind: 'preview', autoOffered: true });
  });

  it('names the lines that are not releases', () => {
    const { entries, invalid } = parseEntries(
      ['26200 9711 5062002 security_monthly 2026-10', 'nonsense', '26200 9711 12 security_monthly 2026-10', '26200 9711 5062002 weekly 2026-10', '26200 9711 5062002 preview 2026-13', '26200 9711 5062002 preview 2026-10 not-a-date'].join('\n'),
    );
    expect(entries).toHaveLength(1);
    expect(invalid).toEqual([2, 3, 4, 5, 6]);
  });
});

describe('currentSecurityMonth', () => {
  it('is the month of the date in UTC', () => {
    expect(currentSecurityMonth(new Date('2026-10-31T23:30:00Z'))).toBe('2026-10');
    expect(currentSecurityMonth(new Date('2027-01-01T00:00:00Z'))).toBe('2027-01');
  });
});
