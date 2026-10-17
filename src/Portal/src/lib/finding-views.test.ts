import { expect, it } from 'vitest';
import { readFindingViews } from './finding-views';

it('restores only known, bounded filter preferences', () => {
  expect(readFindingViews(JSON.stringify([{ name: 'Critical', filters: { severity: ['critical'], technicalState: ['open'] } }]))).toHaveLength(1);
  expect(readFindingViews(JSON.stringify([{ name: 'bad', filters: { organizationId: ['other'] } }]))).toEqual([]);
  expect(readFindingViews(JSON.stringify([{ name: 'bad', filters: { severity: ['unknown'] } }]))).toEqual([]);
  expect(readFindingViews(JSON.stringify([{ name: 'bad', filters: { checkId: ['WIN-999'] } }]))).toEqual([]);
  expect(readFindingViews('{broken')).toEqual([]);
  expect(readFindingViews('x'.repeat(10001))).toEqual([]);
});

it('persists current-user and overdue filters without storing a staff identity', () => {
  const view = { name: 'Mine overdue', filters: { assignedTo: 'me', overdue: 'true', severity: ['critical'] } };
  expect(readFindingViews(JSON.stringify([view]))).toEqual([view]);
  expect(readFindingViews(JSON.stringify([{ name: 'bad', filters: { assignedTo: 'someone' } }]))).toEqual([]);
  expect(readFindingViews(JSON.stringify([{ name: 'bad', filters: { overdue: false } }]))).toEqual([]);
});
