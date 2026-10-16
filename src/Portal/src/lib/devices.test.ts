import { describe, expect, it } from 'vitest';
import { decisionsFor, deviceTone } from './devices';

describe('deviceTone', () => {
  const ok = { status: 'active', dormant: false, identityState: 'ok', clockStatus: 'ok' } as const;
  it('ranks a revoked device, a conflict and a stale one', () => {
    expect(deviceTone(ok)).toBe('good');
    expect(deviceTone({ ...ok, status: 'revoked', identityState: 'identity_conflict' })).toBe('neutral');
    expect(deviceTone({ ...ok, identityState: 'identity_conflict' })).toBe('bad');
    expect(deviceTone({ ...ok, dormant: true })).toBe('warn');
    expect(deviceTone({ ...ok, clockStatus: 'inconsistent' })).toBe('warn');
  });
});

describe('decisionsFor', () => {
  it('offers the decision that fits the kind of the conflict and keep', () => {
    expect(decisionsFor(null)).toEqual([]);
    expect(decisionsFor({ at: '2026-10-14T10:00:00Z', kind: 'fingerprint', reportedDisplayName: null })).toEqual(['accept_new_fingerprint', 'keep']);
    expect(decisionsFor({ at: '2026-10-14T10:00:00Z', kind: 'key', reportedDisplayName: 'PC' })).toEqual(['accept_new_key', 'keep']);
  });
});
