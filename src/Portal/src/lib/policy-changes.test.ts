import { expect, it } from 'vitest';
import { policyChanges } from './policy-changes';

it('identifies only changed policy fields without modifying either snapshot', () => {
  const before = { checks: { 'WIN-001': { parameters: { warnFreePercent: 10, criticalFreePercent: 5 } } }, activeCheckIds: ['WIN-001'] };
  const after = structuredClone(before);
  after.checks['WIN-001'].parameters.warnFreePercent = 20;
  expect(policyChanges(before, after)).toEqual([
    { path: ['checks', 'WIN-001', 'parameters', 'warnFreePercent'], before: 10, after: 20 },
  ]);
  expect(before.checks['WIN-001'].parameters.warnFreePercent).toBe(10);
});

it('ignores ordering of policy sets but shows removals and nullable parameter changes', () => {
  expect(policyChanges({ active: ['WIN-001', 'WIN-002'] }, { active: ['WIN-002', 'WIN-001'] })).toEqual([]);
  expect(policyChanges({ active: ['WIN-001'], expected: 'tenant' }, { active: [], expected: null })).toHaveLength(2);
});
