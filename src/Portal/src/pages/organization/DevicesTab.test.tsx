import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Outlet, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { CurrentStaff, Device, EnrollmentKeySummary, Organization } from '../../api/types';
import { I18nProvider } from '../../i18n/i18n';
import { AuthProvider } from '../../lib/auth';
import { DevicesTab } from './DevicesTab';

const organization = { id: '11111111-1111-4111-8111-111111111111', name: 'Fjord AS', status: 'active', timezone: 'Europe/Oslo', reportLanguage: 'nb', deletionDueAt: null } as unknown as Organization;

const device = (change: Partial<Device>): Device => ({
  id: '22222222-2222-4222-8222-222222222222', displayName: 'PC-ANNE', status: 'active', dormant: false, identityState: 'ok', identityConflict: null,
  clockStatus: 'ok', keyProtection: 'tpm', agentVersion: '0.1.0', enrolledAt: '2026-10-01T08:00:00Z', lastSeenAt: '2026-10-14T08:00:00Z',
  lastFullScanAt: '2026-10-14T07:00:00Z', enrollmentKeyId: null, ...change,
});

const key: EnrollmentKeySummary = {
  id: '33333333-3333-4333-8333-333333333333', label: 'RMM', keyPrefix: 'sikk_AbCd', createdAt: '2026-10-01T08:00:00Z',
  createdBy: '44444444-4444-4444-8444-444444444444', revokedAt: null, lastUsedAt: null, enrolledDevices: 1,
};

const calls: { method: string; path: string; body: unknown }[] = [];

function respond(devices: Device[], keys: EnrollmentKeySummary[]) {
  vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET';
    calls.push({ method, path, body: init?.body ? JSON.parse(init.body as string) : undefined });
    const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
    if (path.includes('/enrollment-keys') && method === 'POST' && !path.endsWith('/revoke')) {
      return json({ id: key.id, enrollmentKey: 'sikk_' + 'x'.repeat(43), label: 'Ny', createdAt: '2026-10-14T09:00:00Z' }, 201);
    }
    if (path.includes('/enrollment-keys')) {
      return method === 'GET' ? json({ items: keys, nextCursor: null }) : new Response(null, { status: 204 });
    }
    if (path.includes('/identity-resolutions')) {
      return json(device({ identityState: 'ok' }));
    }
    if (path.includes('/devices')) {
      return json({ items: devices, nextCursor: null });
    }
    return json({});
  }));
}

function view(roles: CurrentStaff['roles']) {
  const staff = { entraUserId: '55555555-5555-4555-8555-555555555555', displayName: 'Kari', roles, csrfToken: 'x' } as CurrentStaff;
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <I18nProvider initial="en">
      <QueryClientProvider client={client}>
        <AuthProvider staff={staff}>
          <MemoryRouter initialEntries={[`/organizations/${organization.id}/devices`]}>
            <Routes>
              <Route path="organizations/:organizationId" element={<Outlet context={organization} />}>
                <Route path="devices" element={<DevicesTab />} />
              </Route>
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    </I18nProvider>,
  );
}

beforeEach(() => {
  calls.length = 0;
  HTMLDialogElement.prototype.showModal ??= function showModal(this: HTMLDialogElement) { this.setAttribute('open', ''); };
  HTMLDialogElement.prototype.close ??= function close(this: HTMLDialogElement) { this.removeAttribute('open'); };
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('DevicesTab', () => {
  it('lists devices with their state and hides the keys from a technician', async () => {
    respond([device({}), device({ id: '66666666-6666-4666-8666-666666666666', displayName: 'PC-OLA', status: 'revoked' })], [key]);
    view(['Technician']);
    expect(await screen.findByRole('button', { name: 'PC-ANNE' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'PC-OLA' })).toBeTruthy();
    expect(screen.queryByText('Enrollment keys')).toBeNull();
    expect(calls.some((call) => call.path.includes('/enrollment-keys'))).toBe(false);
  });

  it('lets an Admin resolve an identity conflict with the decision that fits its kind', async () => {
    respond([device({ identityState: 'identity_conflict', identityConflict: { at: '2026-10-14T09:00:00Z', kind: 'fingerprint', reportedDisplayName: 'PC-KLON' } })], [key]);
    view(['Admin']);
    await userEvent.click(await screen.findByRole('button', { name: 'PC-ANNE' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/PC-KLON/)).toBeTruthy();
    expect(within(dialog).queryByRole('button', { name: 'Accept the new device key' })).toBeNull();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Accept the new machine identity' }));
    await waitFor(() => expect(calls.some((call) => call.path.endsWith('/identity-resolutions'))).toBe(true));
    expect(calls.find((call) => call.path.endsWith('/identity-resolutions'))?.body).toEqual({ decision: 'accept_new_fingerprint' });
  });

  it('asks for a confirmation before a device is revoked', async () => {
    respond([device({})], [key]);
    view(['Admin']);
    await userEvent.click(await screen.findByRole('button', { name: 'PC-ANNE' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Revoke the device' }));
    expect(calls.some((call) => call.path.endsWith('/revoke'))).toBe(false);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));
    await waitFor(() => expect(calls.some((call) => call.path.endsWith('/devices/22222222-2222-4222-8222-222222222222/revoke'))).toBe(true));
  });

  it('shows a new enrollment key once', async () => {
    respond([], [key]);
    view(['Admin']);
    await userEvent.type(await screen.findByLabelText('Name'), 'Ny');
    await userEvent.click(screen.getByRole('button', { name: 'New key' }));
    expect((await screen.findByTestId('enrollment-secret')).textContent).toBe('sikk_' + 'x'.repeat(43));
    expect(calls.find((call) => call.method === 'POST')?.body).toEqual({ label: 'Ny' });
  });
});
