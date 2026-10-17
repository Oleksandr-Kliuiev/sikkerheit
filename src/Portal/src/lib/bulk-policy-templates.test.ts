import { afterEach, expect, it, vi } from 'vitest';
import type { PolicyTemplatePreview, PolicyTemplatePreviewItem } from '../api/types';
import { applyTemplatePreview } from './bulk-policy-templates';

const row = (id: string): PolicyTemplatePreviewItem => ({ organizationId: id, organizationName: id, policyVersion: 4,
  status: 'ready', previewToken: `signed-${id}`, before: null, after: null, problemCode: null });
const preview = { templateId: 'template', templateRevision: 2, expiresAt: '2030-01-01T00:00:00Z',
  items: [row('first'), row('second'), { ...row('unchanged'), status: 'unchanged' }] } as PolicyTemplatePreview;
afterEach(() => vi.unstubAllGlobals());

it('posts only reviewed tokens and ETags for ready clients, without a client-supplied configuration', async () => {
  const fetch = vi.fn(async (_url: string, _init?: RequestInit) => { void _url; void _init; return Response.json({ policyVersion: 5, replayed: false }); });
  vi.stubGlobal('fetch', fetch);
  const results = await applyTemplatePreview(preview);
  expect(results.map((r) => r.outcome)).toEqual(['applied', 'applied']);
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(JSON.parse(fetch.mock.calls[0]![1]!.body as string)).toEqual({ templateId: 'template', templateRevision: 2, previewToken: 'signed-first' });
  expect(new Headers(fetch.mock.calls[0]![1]!.headers).get('If-Match')).toBe('"4"');
});

it('stops after a version conflict and never silently recomputes or retries the remaining clients', async () => {
  const fetch = vi.fn(async () => Response.json({ code: 'revision_mismatch' }, { status: 412 }));
  vi.stubGlobal('fetch', fetch);
  expect((await applyTemplatePreview(preview)).map((r) => r.outcome)).toEqual(['failed', 'skipped']);
  expect(fetch).toHaveBeenCalledTimes(1);
});

it('marks an uncertain response and confirms it with the identical token on explicit retry', async () => {
  const fetch = vi.fn(async (_url: string, _init?: RequestInit) => { void _url; void _init; throw new TypeError('response lost'); });
  vi.stubGlobal('fetch', fetch);
  const results = await applyTemplatePreview(preview);
  expect(results.map((r) => r.outcome)).toEqual(['unknown', 'skipped']);
  const original = fetch.mock.calls[0]![1];
  vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
    expect(init?.body).toBe(original?.body);
    expect(new Headers(init?.headers).get('If-Match')).toBe('"4"');
    return Response.json({ policyVersion: 5, replayed: true });
  }));
  expect((await applyTemplatePreview(preview, [results[0]!.item]))[0]!.application?.replayed).toBe(true);
});

it('does not start further requests after the page is closed', async () => {
  const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
  expect((await applyTemplatePreview(preview, preview.items, undefined, () => true)).every((r) => r.outcome === 'skipped')).toBe(true);
  expect(fetch).not.toHaveBeenCalled();
});
