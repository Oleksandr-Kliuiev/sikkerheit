import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { dictionaries, translate } from './i18n';
import schema from '../../../../development-package/specs/openapi.json';

// Vitest runs from the portal folder (npm test); jsdom gives import.meta.url no file scheme.
const root = join(process.cwd(), 'src');

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      return sources(path);
    }
    return /\.tsx?$/.test(name) && !name.endsWith('.test.ts') && !name.endsWith('.d.ts') ? [path] : [];
  });
}

describe('portal strings', () => {
  it('have the same keys and placeholders in nb, nn and en', () => {
    const keys = Object.keys(dictionaries.nb).sort();
    for (const language of ['nn', 'en'] as const) {
      expect(Object.keys(dictionaries[language]).sort()).toEqual(keys);
      for (const key of keys) {
        const placeholders = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
        expect(placeholders(dictionaries[language][key]!), `${language} ${key}`).toEqual(placeholders(dictionaries.nb[key]!));
        expect(dictionaries[language][key]!.trim(), `${language} ${key}`).not.toBe('');
      }
    }
  });

  it('contain every literal key used in the code', () => {
    const missing = new Set<string>();
    for (const file of sources(root)) {
      for (const match of readFileSync(file, 'utf8').matchAll(/\bt\('([a-zA-Z0-9_.-]+)'/g)) {
        if (!(match[1]! in dictionaries.nb)) {
          missing.add(`${match[1]} (${file})`);
        }
      }
    }
    expect([...missing]).toEqual([]);
  });

  it('label every closed value the API returns', () => {
    const schemas = (schema as { components: { schemas: Record<string, { properties?: Record<string, { enum?: (string | null)[] }> }> } })
      .components.schemas;
    const values = (component: string, property: string) =>
      (schemas[component]!.properties![property]!.enum ?? []).filter((v): v is string => v !== null);
    const expected = [
      ...values('Problem', 'code').map((v) => `problem.${v}`),
      ...values('Finding', 'workflowState').map((v) => `workflow.${v}`),
      ...values('Finding', 'technicalState').map((v) => `technical.${v}`),
      ...values('Finding', 'severity').map((v) => `severity.${v}`),
      ...values('Finding', 'freshness').map((v) => `freshness.${v}`),
      ...values('FindingEvent', 'eventType').map((v) => `event.${v}`),
      ...values('FindingEvent', 'cause').map((v) => `cause.${v}`),
      ...values('Assessment', 'result').map((v) => `result.${v}`),
      ...values('Assessment', 'reasonCode').map((v) => `reason.${v}`),
      ...values('CollectionRun', 'state').map((v) => `runState.${v}`),
      ...values('CollectionRun', 'failureCode').map((v) => `runFailure.${v}`),
      ...values('CollectionRun', 'trigger').map((v) => `trigger.${v}`),
      ...values('TenantConnection', 'status').map((v) => `connection.status.${v}`),
      ...values('Capability', 'module').map((v) => `module.${v}`),
      ...values('Capability', 'status').map((v) => `capability.${v}`),
      ...values('Organization', 'status').map((v) => `orgStatus.${v}`),
      ...values('Report', 'state').map((v) => `reportState.${v}`),
      ...values('Report', 'failureCode').map((v) => `reportFailure.${v}`),
      ...values('OrganizationExport', 'state').map((v) => `exportState.${v}`),
      ...values('Assessment', 'checkId').map((v) => `check.${v}`),
      ...values('Device', 'status').map((v) => `deviceStatus.${v}`),
      ...values('Device', 'identityState').map((v) => `identity.${v}`),
      ...values('Device', 'clockStatus').map((v) => `clock.${v}`),
      ...values('Device', 'keyProtection').map((v) => `keyProtection.${v}`),
      ...values('WindowsRelease', 'kind').map((v) => `releaseKind.${v}`),
      ...values('WindowsRelease', 'state').map((v) => `releaseState.${v}`),
      ...values('DeviceIdentityResolution', 'decision').map((v) => `devices.decision.${v}`),
    ];
    const conflict = (schemas.Device!.properties!.identityConflict as unknown as { properties: Record<string, { enum: string[] }> }).properties;
    expected.push(...conflict.kind!.enum.map((v) => `conflictKind.${v}`));
    expect(expected.filter((key) => !(key in dictionaries.nb))).toEqual([]);
  });

  it('fill placeholders and fall back to the key', () => {
    expect(translate('en', 'reports.weekLabel', { week: 41, year: 2026 })).toBe('Week 41 2026');
    expect(translate('nn', 'no.such.key')).toBe('no.such.key');
  });
});
