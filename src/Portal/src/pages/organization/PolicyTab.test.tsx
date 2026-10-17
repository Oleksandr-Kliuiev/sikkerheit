import { readFileSync } from 'node:fs';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Outlet, Route, Routes } from 'react-router';
import { afterEach, expect, it, vi } from 'vitest';
import type { CurrentStaff, PolicyConfiguration } from '../../api/types';
import { I18nProvider } from '../../i18n/i18n';
import { AuthProvider } from '../../lib/auth';
import { PolicyTab } from './PolicyTab';

type Schema = { default?: unknown; properties?: Record<string, Schema> };
const contract = JSON.parse(readFileSync('../../development-package/specs/openapi.json', 'utf8'));
function defaults(schema: Schema): unknown {
  return 'default' in schema ? structuredClone(schema.default)
    : Object.fromEntries(Object.entries(schema.properties ?? {}).map(([key, value]) => [key, defaults(value)]));
}

function view(role: 'Admin' | 'Reader') {
  const configuration = defaults(contract.components.schemas.PolicyConfiguration) as PolicyConfiguration;
  const saved: { configuration: PolicyConfiguration; etag: string | null }[] = [];
  const revision = { version: 1, effectiveFrom: '2026-10-17T09:00:00Z', configuration };
  vi.stubGlobal('fetch', vi.fn(async (_path: string, init?: RequestInit) => {
    if (init?.method === 'POST') {
      const body = JSON.parse(init.body as string);
      saved.push({ configuration: body.configuration, etag: new Headers(init.headers).get('If-Match') });
      return Response.json({ ...revision, version: 2, configuration: body.configuration }, { status: 201 });
    }
    return Response.json({ items: [revision], nextCursor: null });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<I18nProvider initial="en"><QueryClientProvider client={client}>
    <AuthProvider staff={{ roles: [role], csrfToken: 'test' } as CurrentStaff}>
      <MemoryRouter initialEntries={['/organizations/11111111-1111-4111-8111-111111111111/policy']}>
        <Routes><Route path="organizations/:organizationId" element={<Outlet />}>
          <Route path="policy" element={<PolicyTab />} />
        </Route></Routes>
      </MemoryRouter>
    </AuthProvider>
  </QueryClientProvider></I18nProvider>);
  return { saved, configuration };
}

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('saves Windows thresholds, agent settings and provider lists as a new revision while preserving the rest', async () => {
  const { saved, configuration } = view('Admin');
  const interval = await screen.findByLabelText('Scan interval (hours)');
  await userEvent.clear(interval);
  await userEvent.type(interval, '48');
  await userEvent.type(screen.getByLabelText('Approved antivirus providers'), 'Example AV');
  await userEvent.click(screen.getByLabelText('Require Secure Boot'));
  expect((screen.getByLabelText('Active WIN-011') as HTMLInputElement).disabled).toBe(true);
  await userEvent.click(screen.getByRole('button', { name: 'Save a new policy version' }));
  expect(saved).toHaveLength(0);
  expect(await screen.findByRole('heading', { name: 'Review policy changes' })).toBeTruthy();
  await userEvent.click(screen.getByRole('button', { name: 'Apply policy changes' }));
  await waitFor(() => expect(saved).toHaveLength(1));
  expect(saved[0]!.etag).toBe('"1"');
  expect(saved[0]!.configuration.agent.scanIntervalHours).toBe(48);
  expect(saved[0]!.configuration.checks['WIN-003'].parameters.approvedProviders).toEqual(['Example AV']);
  expect(saved[0]!.configuration.checks['WIN-009'].parameters.secureBootRequired).toBe(false);
  expect(saved[0]!.configuration.m365).toEqual(configuration.m365);
  expect(saved[0]!.configuration.checks['M365-003']).toEqual(configuration.checks['M365-003']);
  expect(saved[0]!.configuration.activeCheckIds).toContain('WIN-011');
});

it('keeps a reader from editing Windows policies', async () => {
  const { saved } = view('Reader');
  const interval = await screen.findByLabelText('Scan interval (hours)');
  expect(interval.matches(':disabled')).toBe(true);
  expect(screen.queryByRole('button', { name: 'Save a new policy version' })).toBeNull();
  expect(saved).toHaveLength(0);
});

it('never offers assessed mode for the informational-only health checks', async () => {
  view('Admin');
  await screen.findByLabelText('Scan interval (hours)');
  for (const id of ['M365-007', 'WIN-011', 'SYS-001']) {
    const control = screen.getByLabelText(`Mode ${id}`) as HTMLSelectElement;
    expect(control.disabled).toBe(true);
    expect([...control.options].map((option) => option.value)).toEqual(['informational']);
  }
  expect((screen.getByLabelText('Mode SYS-002') as HTMLSelectElement).disabled).toBe(false);
});

it('does not submit a malformed domain RID list', async () => {
  const { saved } = view('Admin');
  const rids = await screen.findByLabelText('Allowed domain group RIDs');
  await userEvent.clear(rids);
  await userEvent.type(rids, 'not-a-rid');
  await userEvent.click(screen.getByRole('button', { name: 'Save a new policy version' }));
  expect(saved).toHaveLength(0);
  expect((rids as HTMLTextAreaElement).checkValidity()).toBe(false);
});

it('allows cancelling a preview and prevents saving an unchanged revision', async () => {
  const { saved } = view('Admin');
  await screen.findByLabelText('Scan interval (hours)');
  await userEvent.click(screen.getByRole('button', { name: 'Save a new policy version' }));
  expect(await screen.findByText('There are no policy changes to save.')).toBeTruthy();
  expect((screen.getByRole('button', { name: 'Apply policy changes' }) as HTMLButtonElement).disabled).toBe(true);
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(saved).toHaveLength(0);
});

it('previews a template, applies only to the draft, then saves with the original ETag after a separate review', async () => {
  const { saved } = view('Admin');
  await screen.findByLabelText('Template');
  await userEvent.selectOptions(screen.getByLabelText('Template'), 'm365-stronger-mfa');
  await userEvent.click(screen.getByRole('button', { name: 'Preview template changes' }));
  await screen.findByRole('heading', { name: 'Review template: Microsoft 365 — MFA without phone methods' });
  expect(saved).toHaveLength(0);
  await userEvent.click(screen.getByRole('button', { name: 'Apply to draft' }));
  expect(saved).toHaveLength(0);
  expect((screen.getByLabelText('Phone (SMS/voice) counts as an MFA method') as HTMLInputElement).checked).toBe(false);
  await userEvent.click(screen.getByRole('button', { name: 'Save a new policy version' }));
  await userEvent.click(await screen.findByRole('button', { name: 'Apply policy changes' }));
  await waitFor(() => expect(saved).toHaveLength(1));
  expect(saved[0]!.etag).toBe('"1"');
  expect(saved[0]!.configuration.checks['M365-001'].parameters.phoneMethodsAccepted).toBe(false);
});
