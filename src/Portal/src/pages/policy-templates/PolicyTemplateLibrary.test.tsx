import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { afterEach, expect, it, vi } from 'vitest';
import type { CurrentStaff, PolicyConfiguration, PolicyTemplate } from '../../api/types';
import { I18nProvider } from '../../i18n/i18n';
import { AuthProvider } from '../../lib/auth';
import defaults from '../../lib/policy-defaults.g.json';
import { extractTemplateContent } from '../../lib/shared-policy-templates';
import { PolicyTemplateLibrary } from './PolicyTemplateLibrary';

const id = '11111111-1111-4111-8111-111111111111';
const template: PolicyTemplate = { id, revision: 1, name: 'Pilot MFA', description: 'Shared template',
  archived: false, createdAt: '2026-10-17T12:00:00Z', createdBy: id,
  content: extractTemplateContent(defaults as PolicyConfiguration, 'm365') };
function view(role: 'Admin' | 'Reader', initial = true) {
  let templates = initial ? [template] : [];
  const posts: { url: string; body: Record<string, unknown> }[] = [];
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    const body = init?.body ? JSON.parse(init.body as string) : undefined;
    if (init?.method === 'POST') {
      posts.push({ url, body });
      if (url.endsWith('/preview')) {
        const after = structuredClone(defaults) as PolicyConfiguration;
        after.checks['M365-001'].parameters.phoneMethodsAccepted = false;
        return Response.json({ templateId: id, templateRevision: 1, expiresAt: '2030-01-01T12:00:00Z',
          items: [{ organizationId: id, organizationName: 'Fjord AS', status: 'ready', policyVersion: 1,
            before: defaults, after, previewToken: 'signed-preview', problemCode: null }] });
      }
      if (url.endsWith('/policy-template-applications')) return Response.json({ templateId: id, templateRevision: 1, policyVersion: 2, appliedAt: '2026-10-17T12:00:00Z', replayed: false });
      templates = [{ ...template, ...body }]; return Response.json(templates[0], { status: 201 });
    }
    if (url.includes('/staff')) return Response.json({ items: [], nextCursor: null });
    if (url.startsWith('/api/v1/organizations')) return Response.json({ items: [{ organization: { id, name: 'Fjord AS', status: 'active' } }], nextCursor: null });
    return Response.json({ items: templates, nextCursor: null });
  });
  vi.stubGlobal('fetch', fetch);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<I18nProvider initial="en"><QueryClientProvider client={client}><AuthProvider staff={{ roles: [role], entraUserId: id } as CurrentStaff}>
    <MemoryRouter><PolicyTemplateLibrary /></MemoryRouter>
  </AuthProvider></QueryClientProvider></I18nProvider>);
  return posts;
}
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('saves a portable template only after preview, without changing a customer policy', async () => {
  const posts = view('Admin', false);
  await userEvent.click(screen.getByRole('button', { name: 'New template' }));
  await userEvent.type(screen.getByLabelText('Template name'), 'New shared baseline');
  await userEvent.click(screen.getByText('MFA method for users', { exact: false }).closest('summary')!);
  await userEvent.click(screen.getByLabelText('Phone (SMS/voice) counts as an MFA method'));
  await userEvent.click(screen.getByRole('button', { name: 'Review template version' }));
  expect(posts).toHaveLength(0);
  const dialog = await screen.findByRole('dialog');
  expect(within(dialog).getByText('New shared baseline')).toBeTruthy();
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save template version' }));
  await waitFor(() => expect(posts).toHaveLength(1));
  expect(posts[0]!.url).toBe('/api/v1/policy-templates');
  expect(JSON.stringify(posts[0]!.body)).not.toContain('excludedUserIds');
});

it('requires a per-client preview before starting bulk application', async () => {
  const posts = view('Admin');
  await userEvent.click(await screen.findByRole('button', { name: /Pilot MFA · Version 1/ }));
  await userEvent.click(screen.getByRole('button', { name: 'Apply to customers' }));
  await userEvent.click(await screen.findByLabelText('Fjord AS'));
  expect(screen.queryByRole('button', { name: /Apply to 1 reviewed/ })).toBeNull();
  await userEvent.click(screen.getByRole('button', { name: 'Preview selected customers' }));
  const apply = await screen.findByRole('button', { name: 'Apply to 1 reviewed customers' });
  expect(posts).toHaveLength(1);
  expect(screen.getByRole('rowheader', { name: /Phone \(SMS\/voice\) counts as an MFA method/ })).toBeTruthy();
  await userEvent.click(apply);
  await screen.findByText('Saved policy version 2.');
  expect(posts).toHaveLength(2);
  expect(posts[1]!.body.previewToken).toBe('signed-preview');
});

it('lets readers inspect shared templates without editing or application controls', async () => {
  view('Reader');
  await userEvent.click(await screen.findByRole('button', { name: /Pilot MFA · Version 1/ }));
  expect(screen.queryByRole('button', { name: 'New template' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Edit template' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Apply to customers' })).toBeNull();
  expect(screen.getByText('Template settings')).toBeTruthy();
});
