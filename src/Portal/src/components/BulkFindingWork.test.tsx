import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import type { Finding } from '../api/types';
import { I18nProvider } from '../i18n/i18n';
import { BulkFindingWork } from './BulkFindingWork';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('previews current assignments and sends no changes until the reviewed batch is confirmed', async () => {
  const finding = { id: 'finding-1', organizationId: 'org-a', title: 'Missing MFA', technicalState: 'open', workflowState: 'new',
    assigneeId: null, dueAt: null } as Finding;
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.includes('/staff')) return Response.json({ items: [{ entraUserId: 'worker', displayName: 'Technician', active: true, roles: ['Technician'] }], nextCursor: null });
    if (init?.method === 'PATCH') return Response.json({ ...finding, assigneeId: 'worker' });
    return Response.json(finding, { headers: { ETag: '"7"' } });
  });
  vi.stubGlobal('fetch', fetch);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const clear = vi.fn();
  render(<I18nProvider initial="en"><QueryClientProvider client={client}>
    <BulkFindingWork selected={[finding]} organizationNames={new Map([['org-a', 'Fjord AS']])} onClear={clear} />
  </QueryClientProvider></I18nProvider>);
  await screen.findByRole('option', { name: 'Technician' });
  await userEvent.selectOptions(screen.getByLabelText('Assignee'), 'worker');
  await userEvent.click(screen.getByRole('button', { name: 'Review selected changes' }));
  expect(await screen.findByRole('heading', { name: 'Review bulk changes' })).toBeTruthy();
  expect(screen.getByText('Fjord AS')).toBeTruthy();
  expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(0);
  await userEvent.click(screen.getByRole('button', { name: 'Apply to 1 findings' }));
  await waitFor(() => expect(screen.getByText('Applied')).toBeTruthy());
  const writes = fetch.mock.calls.filter(([, init]) => init?.method === 'PATCH');
  expect(writes).toHaveLength(1);
  expect(new Headers(writes[0]![1]!.headers).get('If-Match')).toBe('"7"');
  expect(clear).not.toHaveBeenCalled();
});
