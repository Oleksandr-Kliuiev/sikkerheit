import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import type { CurrentStaff, Finding } from '../api/types';
import { I18nProvider } from '../i18n/i18n';
import { AuthProvider } from '../lib/auth';
import { FindingsList } from './Findings';

function view(role: 'Technician' | 'Reader') {
  const findings = [1, 2].map((id) => ({ id: `finding-${id}`, organizationId: 'org-a', title: `Missing MFA ${id}`,
    technicalState: 'open', workflowState: 'new', severity: 'critical', freshness: 'fresh', checkId: 'M365-001',
    subject: { type: 'user', displayName: 'Synthetic user', key: 'user' }, openedAt: '2026-10-17T10:00:00Z',
    dueAt: null, assigneeId: null } as Finding));
  const fetch = vi.fn(async (url: string) => {
    if (url.includes('/staff')) return Response.json({ items: [{ entraUserId: 'worker', displayName: 'Technician', active: true, roles: ['Technician'] }], nextCursor: null });
    if (url.includes('/organizations/')) return Response.json(findings.find((finding) => url.endsWith(finding.id)), { headers: { ETag: '"7"' } });
    return Response.json({ items: findings, nextCursor: 'unloaded-page' });
  });
  vi.stubGlobal('fetch', fetch);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<I18nProvider initial="en"><QueryClientProvider client={client}>
    <AuthProvider staff={{ entraUserId: 'worker', roles: [role], csrfToken: 'synthetic' } as CurrentStaff}>
      <FindingsList organizationId={null} />
    </AuthProvider>
  </QueryClientProvider></I18nProvider>);
  return fetch;
}

afterEach(() => { cleanup(); localStorage.clear(); vi.unstubAllGlobals(); });

it('selects only loaded rows and never silently includes an unloaded page in bulk changes', async () => {
  const fetch = view('Technician');
  await screen.findByText('Missing MFA 1');
  await userEvent.click(screen.getByLabelText('Select up to 50 loaded findings'));
  expect(screen.getByText('Selected: 2 (maximum 50). Only selected findings are changed.')).toBeTruthy();
  await screen.findByRole('option', { name: 'Technician' });
  await userEvent.selectOptions(screen.getByLabelText('Assignee'), 'worker');
  await userEvent.click(screen.getByRole('button', { name: 'Review selected changes' }));
  expect(await screen.findByRole('heading', { name: 'Review bulk changes' })).toBeTruthy();
  expect(fetch.mock.calls.some(([url]) => url.includes('unloaded-page'))).toBe(false);
});

it('does not offer bulk mutations to readers', async () => {
  view('Reader');
  await screen.findByText('Missing MFA 1');
  expect(screen.queryByLabelText('Select up to 50 loaded findings')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Review selected changes' })).toBeNull();
});

it('combines My tasks and Overdue as server filters and resets cursor pagination when changing views', async () => {
  const fetch = view('Technician');
  await screen.findByText('Missing MFA 1');
  await userEvent.click(screen.getByRole('button', { name: 'My tasks' }));
  await screen.findByText('Missing MFA 1');
  await userEvent.click(screen.getByRole('button', { name: 'Overdue' }));
  await screen.findByText('Missing MFA 1');
  expect(fetch.mock.calls.some(([url]) => url.includes('assignedTo=me') && url.includes('overdue=true') && !url.includes('cursor='))).toBe(true);
  expect(screen.getByRole('button', { name: 'My tasks' }).getAttribute('aria-pressed')).toBe('true');
  await userEvent.click(screen.getByRole('button', { name: 'My tasks' }));
  expect(screen.getByRole('button', { name: 'My tasks' }).getAttribute('aria-pressed')).toBe('false');
  expect(screen.getByRole('button', { name: 'Overdue' }).getAttribute('aria-pressed')).toBe('true');
});
