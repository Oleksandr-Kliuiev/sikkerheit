import type { WindowsReleaseImport } from '../api/types';

export type ReleaseEntry = NonNullable<WindowsReleaseImport['entries']>[number];

export const releaseKinds = ['security_monthly', 'security_oob', 'nonsecurity_oob', 'preview', 'hotpatch'] as const;

const month = /^\d{4}-(0[1-9]|1[0-2])$/;

export interface ParsedEntries {
  entries: ReleaseEntry[];
  /** 1-based line numbers that are not an entry. */
  invalid: number[];
}

/**
 * Manual entries of a month, one per line: «branch ubr kb kind securityMonth [date] [auto|manual]» — for example
 * «26200 9711 5062002 security_monthly 2026-10 2026-10-13». The month «-» means a release without security fixes.
 */
export function parseEntries(text: string): ParsedEntries {
  const entries: ReleaseEntry[] = [];
  const invalid: number[] = [];
  text.split('\n').forEach((raw, index) => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) {
      return;
    }
    const [branch, ubr, kb, kind, securityMonth, date, offered] = line.split(/\s+/);
    const releaseAt = date ? new Date(`${date}T00:00:00Z`) : null;
    const ok =
      /^\d{5,}$/.test(branch ?? '') &&
      /^\d+$/.test(ubr ?? '') &&
      /^\d{6,8}$/.test(kb ?? '') &&
      (releaseKinds as readonly string[]).includes(kind ?? '') &&
      (securityMonth === '-' || month.test(securityMonth ?? '')) &&
      (releaseAt === null || !Number.isNaN(releaseAt.getTime())) &&
      (offered === undefined || offered === 'auto' || offered === 'manual');
    if (!ok) {
      invalid.push(index + 1);
      return;
    }
    entries.push({
      branchBuild: Number(branch),
      ubr: Number(ubr),
      kb: kb!,
      kind: kind as ReleaseEntry['kind'],
      securityMonth: securityMonth === '-' ? null : securityMonth!,
      releaseAt: (releaseAt ?? new Date(`${securityMonth === '-' ? '2000-01' : securityMonth}-13T00:00:00Z`)).toISOString(),
      autoOffered: offered !== 'manual',
    });
  });
  return { entries, invalid };
}

/** The previous completed month (YYYY-MM) of a date, the one an Admin verifies in the week after Patch Tuesday. */
export function currentSecurityMonth(now: Date): string {
  const month = String(now.getUTCMonth() + 1).padStart(2, '0');
  return `${now.getUTCFullYear()}-${month}`;
}
