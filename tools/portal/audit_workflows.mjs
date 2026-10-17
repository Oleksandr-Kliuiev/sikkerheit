/** Local portal workflow smoke test with synthetic API data. No Azure, Graph or Atera traffic.
 * PLAYWRIGHT_MODULE=/absolute/path/to/playwright UI_AUDIT_MODULE=/absolute/path/to/audit.mjs node tools/portal/audit_workflows.mjs
 */
import { createRequire } from 'node:module';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const { auditPage, auditTitles } = await import(pathToFileURL(process.env.UI_AUDIT_MODULE).href);
const root = resolve(import.meta.dirname, '../..');
const out = resolve(root, process.env.UI_AUDIT_OUT || '.dev/portal-audit');
await mkdir(out, { recursive: true });
const config = JSON.parse(await readFile(resolve(root, 'src/Portal/src/lib/policy-defaults.g.json'), 'utf8'));
const orgId = '11111111-1111-4111-8111-111111111111';
const workerId = '22222222-2222-4222-8222-222222222222';
const now = new Date().toISOString();
const organization = { id: orgId, name: 'Fjord AS', timezone: 'Europe/Oslo', reportLanguage: 'nb', status: 'active', createdAt: now };
const me = { entraUserId: workerId, displayName: 'Pilot Technician', roles: ['Admin'], csrfToken: 'synthetic' };
const finding = { id: '33333333-3333-4333-8333-333333333333', organizationId: orgId, checkId: 'M365-001',
  subject: { type: 'user', key: 'synthetic-user', displayName: 'Synthetic user', deviceId: null }, technicalState: 'open',
  workflowState: 'new', assessmentResult: 'fail', freshness: 'fresh', severity: 'critical', revision: 1,
  title: 'User without a registered MFA method', recommendation: 'Register an approved MFA method.',
  openedAt: now, latestObservedAt: now, assigneeId: workerId, dueAt: '2026-01-01T09:00:00Z' };
const revision = { organizationId: orgId, version: 1, effectiveFrom: now, createdAt: now, createdBy: workerId, configuration: config };
const pageOf = (items) => ({ items, nextCursor: null });
const portableMetadata = JSON.parse(await readFile(resolve(root, 'src/Portal/src/lib/policy-template-fields.g.json'), 'utf8'));
const portableChecks = Object.fromEntries(portableMetadata.scopes.m365.map((id) => [id, {
  assessmentMode: config.checks[id].assessmentMode, freshnessWindowHours: config.checks[id].freshnessWindowHours,
  parameters: Object.fromEntries(Object.entries(config.checks[id].parameters)
    .filter(([name]) => !(portableMetadata.protectedParameters[id] || []).includes(name))),
}]));
portableChecks['M365-001'].parameters.phoneMethodsAccepted = false;
const libraryTemplate = { id: '44444444-4444-4444-8444-444444444444', revision: 1, name: 'Pilot MFA',
  description: 'Portable assessment settings for a customer pilot.', archived: false, createdAt: now, createdBy: workerId,
  content: { scope: 'm365', activeCheckIds: [...portableMetadata.scopes.m365], checks: portableChecks } };
const afterTemplate = structuredClone(config);
afterTemplate.checks['M365-001'].parameters.phoneMethodsAccepted = false;
const browser = await chromium.launch(process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {});
const results = [];
const titles = {};
let posts = 0;
try {
  for (const theme of ['light', 'dark']) for (const width of [1440, 768, 390, 320]) {
    const context = await browser.newContext({ viewport: { width, height: 960 }, colorScheme: theme });
    await context.addInitScript(() => localStorage.setItem('sikkerheit.language', 'en'));
    await context.route('**/api/v1/**', async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      let body = pageOf([]);
      const headers = { 'Content-Language': 'en', ETag: '"1"' };
      if (path.includes('/policy-templates/') && path.endsWith('/preview')) {
        body = { templateId: libraryTemplate.id, templateRevision: 1, expiresAt: '2030-01-01T12:00:00Z',
          items: [{ organizationId: orgId, organizationName: organization.name, status: 'ready', policyVersion: 1,
            before: config, after: afterTemplate, previewToken: 'synthetic-signed-preview', problemCode: null }] };
      }
      else if (path.endsWith('/policy-template-applications')) body = { templateId: libraryTemplate.id, templateRevision: 1,
        policyVersion: 2, appliedAt: now, replayed: false };
      else if (path.endsWith('/policy-templates') || (path.includes('/policy-templates/') && path.endsWith('/revisions'))) body = pageOf([libraryTemplate]);
      else if (path.includes('/policy-templates/')) body = libraryTemplate;
      else if (path.endsWith('/me')) body = me;
      else if (path.endsWith('/policy-revisions')) {
        if (request.method() === 'POST') { posts++; body = { ...revision, version: 2, configuration: request.postDataJSON().configuration }; }
        else body = pageOf([revision]);
      }
      else if (path.endsWith('/staff')) body = pageOf([{ ...me, active: true }]);
      else if (path.endsWith('/m365-connection')) body = { status: 'not_connected', entraP1: null, capabilities: [] };
      else if (path.endsWith('/findings/' + finding.id)) body = finding;
      else if (path.endsWith('/findings')) body = pageOf([finding]);
      else if (path === '/api/v1/organizations') body = pageOf([{ organization, m365Status: 'not_connected', coverage: null, openCritical: 1, openWarning: 0 }]);
      else if (path === '/api/v1/organizations/' + orgId) body = organization;
      await route.fulfill({ status: request.method() === 'POST' ? 201 : 200, contentType: 'application/json', headers, body: JSON.stringify(body) });
    });
    // Prevent unexpected external calls; only Vite and mocked API calls are used.
    await context.route(/^https?:\/\/(?!127\.0\.0\.1:5173)/, (route) => route.abort());
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    async function capture(name) {
      const findings = await auditPage(page);
      results.push({ name, width, theme, findings, runtimeErrors: [...errors] });
      titles[name] = await page.title();
      await writeFile(resolve(out, 'audit-progress.json'), JSON.stringify({ results, titles }, null, 2));
      if (['policy', 'policy-checks', 'template-review', 'tasks'].includes(name) || name.startsWith('library')) {
        await page.screenshot({ path: resolve(out, `${name}-${width}-${theme}-viewport.png`) });
      }
      await page.screenshot({ path: resolve(out, `${name}-${width}-${theme}.png`), fullPage: true });
    }
    const base = 'http://127.0.0.1:5173';
    await page.goto(base + '/findings');
    await page.getByRole('button', { name: 'My tasks', exact: true }).click();
    await page.getByRole('button', { name: 'Overdue', exact: true }).click();
    await page.getByText(finding.title, { exact: true }).waitFor();
    await capture('tasks');
    await page.goto(`${base}/organizations/${orgId}/policy`);
    await page.getByLabel('Template', { exact: true }).selectOption('m365-stronger-mfa');
    await capture('policy');
    for (const id of ['M365-007', 'WIN-011', 'SYS-001']) {
      const mode = page.getByLabel(`Mode ${id}`, { exact: true });
      if (!await mode.isDisabled() || await mode.locator('option').count() !== 1
        || await mode.inputValue() !== 'informational') throw new Error(`Invalid policy modes offered for ${id}`);
    }
    await page.getByLabel('Mode WIN-011', { exact: true }).scrollIntoViewIfNeeded();
    await capture('policy-checks');
    await page.getByRole('button', { name: 'Preview template changes', exact: true }).click();
    await page.getByRole('dialog').waitFor();
    await capture('template-review');
    await page.getByRole('button', { name: 'Apply to draft', exact: true }).click();
    if (posts !== 0) throw new Error('Template application unexpectedly persisted a policy');
    if (await page.getByLabel('Phone (SMS/voice) counts as an MFA method', { exact: true }).isChecked()) throw new Error('Template was not applied');
    // Visit every other authenticated page/tab to check shared layout changes.
    for (const [name, path] of Object.entries({ organizations: '/organizations', overview: `/organizations/${orgId}`,
      'org-findings': `/organizations/${orgId}/findings`, assessments: `/organizations/${orgId}/assessments`,
      devices: `/organizations/${orgId}/devices`, reports: `/organizations/${orgId}/reports`,
      settings: `/organizations/${orgId}/settings`, staff: '/staff', releases: '/windows-releases' })) {
      await page.goto(base + path);
      await page.locator('main h1').waitFor({ timeout: 5000 }).catch(async (error) => { throw new Error(`${name}: ${error.message}; runtime: ${errors.join('; ')}`); });
      await page.waitForTimeout(80);
      await capture(name);
    }
    await page.goto(base + '/policy-templates');
    await page.getByRole('button', { name: 'Pilot MFA · Version 1', exact: true }).click();
    await capture('library');
    await page.getByRole('button', { name: 'New template', exact: true }).click();
    await page.getByLabel('Template name', { exact: true }).fill('Pilot security baseline');
    await page.locator('summary').filter({ hasText: 'MFA method for users' }).click();
    await page.getByLabel('Phone (SMS/voice) counts as an MFA method', { exact: true }).uncheck();
    await capture('library-editor');
    await page.getByRole('button', { name: 'Review template version', exact: true }).click();
    await page.getByRole('dialog').waitFor();
    await capture('library-save-review');
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    await page.getByRole('button', { name: 'Apply to customers', exact: true }).click();
    await page.getByLabel('Fjord AS', { exact: true }).check();
    await page.getByRole('button', { name: 'Preview selected customers', exact: true }).click();
    await page.getByRole('button', { name: 'Apply to 1 reviewed customers', exact: true }).waitFor();
    await capture('library-bulk-review');
    await page.getByRole('button', { name: 'Apply to 1 reviewed customers', exact: true }).click();
    await page.getByText('Saved policy version 2.', { exact: true }).waitFor();
    await capture('library-bulk-result');
    await context.close();
  }
} finally { await browser.close(); }
// Review dialog and organization tabs deliberately share the enclosing page title.
const titleFindings = auditTitles(Object.fromEntries(['tasks', 'policy', 'organizations', 'staff', 'releases', 'library'].map((name) => [name, titles[name]])));
await writeFile(resolve(out, 'audit.json'), JSON.stringify({ results, titleFindings }, null, 2));
const counts = {};
for (const result of results) for (const item of result.findings) counts[item.rule] = (counts[item.rule] || 0) + 1;
console.log(JSON.stringify({ captures: results.length, counts, titleFindings, runtimeErrors: results.flatMap((r) => r.runtimeErrors), report: resolve(out, 'audit.json') }, null, 2));
if (results.some((r) => r.findings.some((f) => f.level === 'error') || r.runtimeErrors.length)) process.exitCode = 1;
