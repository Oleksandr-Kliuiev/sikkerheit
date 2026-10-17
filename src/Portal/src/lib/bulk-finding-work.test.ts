import { afterEach, expect, it, vi } from 'vitest';
import { ApiError } from '../api/client';
import type { Finding } from '../api/types';
import { applyFindingWork, prepareFindingWork } from './bulk-finding-work';

const first = { id: 'first', organizationId: 'org-a', technicalState: 'open', workflowState: 'new', title: 'First', assigneeId: null, dueAt: null } as Finding;
const second = { ...first, id: 'second', organizationId: 'org-b', title: 'Second' };
afterEach(() => vi.unstubAllGlobals());

it('refreshes selected findings and preserves the exact reviewed revision for each organization', async () => {
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    const finding = url.includes('org-a') ? first : second;
    if (init?.method === 'PATCH') return Response.json({ ...finding, assigneeId: 'worker' });
    return Response.json(finding, { headers: { ETag: finding === first ? '"7"' : '"9"' } });
  });
  vi.stubGlobal('fetch', fetch);
  const plans = await prepareFindingWork([first, second, first], { assigneeId: 'worker' });
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(fetch.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
  const results = await applyFindingWork(plans);
  expect(results.map((result) => result.outcome)).toEqual(['applied', 'applied']);
  const writes = fetch.mock.calls.filter(([, init]) => init?.method === 'PATCH');
  expect(writes.map(([, init]) => new Headers(init!.headers).get('If-Match'))).toEqual(['"7"', '"9"']);
  expect(writes.map(([url]) => url)).toEqual(['/api/v1/organizations/org-a/findings/first', '/api/v1/organizations/org-b/findings/second']);
});

it('does not overwrite a conflicting revision and never retries mutations automatically', async () => {
  const fetch = vi.fn(async (url: string) => url.includes('/first')
    ? Response.json({ code: 'precondition_failed' }, { status: 412 }) : Response.json(second));
  vi.stubGlobal('fetch', fetch);
  const results = await applyFindingWork([
    { finding: first, etag: '"7"', change: { dueAt: null } }, { finding: second, etag: '"9"', change: { dueAt: null } },
  ]);
  expect(results.map((result) => result.outcome)).toEqual(['failed', 'applied']);
  expect(fetch).toHaveBeenCalledTimes(2);
});

it('stops after an ambiguous network result and leaves remaining findings unattempted', async () => {
  const fetch = vi.fn(async () => { throw new Error('network disconnected after commit'); });
  vi.stubGlobal('fetch', fetch);
  const results = await applyFindingWork([
    { finding: first, etag: '"7"', change: { assigneeId: 'worker' } }, { finding: second, etag: '"9"', change: { assigneeId: 'worker' } },
  ]);
  expect(results.map((result) => result.outcome)).toEqual(['unknown', 'skipped']);
  expect(fetch).toHaveBeenCalledTimes(1);
});

it('refuses an unsafe preview when one finding is no longer actionable or lacks a revision', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({ ...first, workflowState: 'risk_accepted' }, { headers: { ETag: '"8"' } })));
  await expect(prepareFindingWork([first], { assigneeId: 'worker' })).rejects.toBeInstanceOf(ApiError);
  vi.stubGlobal('fetch', vi.fn(async () => Response.json(first)));
  await expect(prepareFindingWork([first], { assigneeId: 'worker' })).rejects.toBeInstanceOf(ApiError);
});

it('stops the batch when access is revoked', async () => {
  const fetch = vi.fn(async () => Response.json({ code: 'forbidden' }, { status: 403 }));
  vi.stubGlobal('fetch', fetch);
  const results = await applyFindingWork([
    { finding: first, etag: '"7"', change: { assigneeId: 'worker' } }, { finding: second, etag: '"9"', change: { assigneeId: 'worker' } },
  ]);
  expect(results.map((result) => result.outcome)).toEqual(['failed', 'skipped']);
  expect(fetch).toHaveBeenCalledTimes(1);
});

it('does not create changes for the same deadline in another timezone representation', async () => {
  const finding = { ...first, dueAt: '2026-10-20T12:00:00+00:00' };
  vi.stubGlobal('fetch', vi.fn(async () => Response.json(finding, { headers: { ETag: '"8"' } })));
  expect(await prepareFindingWork([finding], { dueAt: '2026-10-20T14:00:00+02:00' })).toEqual([]);
});
