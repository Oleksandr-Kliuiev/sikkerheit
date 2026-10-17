import { expect, it } from 'vitest';
import type { PolicyConfiguration } from '../api/types';
import defaults from './policy-defaults.g.json';
import { applyPolicyTemplate } from './policy-templates';

function customer() {
  const result = structuredClone(defaults) as PolicyConfiguration;
  result.m365.excludedUserIds = ['11111111-1111-4111-8111-111111111111'];
  result.m365.collectionHourLocal = 15;
  result.agent.scanIntervalHours = 48;
  result.checks['M365-002'].parameters.privilegedRoleTemplateIds = ['22222222-2222-4222-8222-222222222222'];
  result.checks['M365-006'].parameters.allowedPermissionGrantPolicies = ['CustomPolicy'];
  result.checks['WIN-010'].parameters.expectedTenantId = '33333333-3333-4333-8333-333333333333';
  result.checks['WIN-003'].parameters = { defenderApproved: false, approvedProviders: ['Customer AV'] };
  result.checks['WIN-005'].parameters.approvedFirewallProviders = ['Customer firewall'];
  result.checks['WIN-008'].parameters.allowedSids = ['S-1-5-21-1-2-3-1001'];
  result.checks['WIN-008'].parameters.allowedDomainRids = [513];
  result.checks['WIN-002'].notApplicableEditionIds = ['Core'];
  return result;
}

it('scopes the M365 preset and preserves customer inputs, schedules and deferred checks without mutating the draft', () => {
  const draft = customer();
  const snapshot = structuredClone(draft);
  draft.checks['M365-003'].assessmentMode = 'informational';
  draft.checks['M365-003'].parameters.deviceAlternativeAccepted = true;
  const result = applyPolicyTemplate(draft, 'm365-stronger-mfa');
  expect(result.m365).toEqual(snapshot.m365);
  expect(result.agent).toEqual(snapshot.agent);
  expect(result.checks['WIN-003']).toEqual(snapshot.checks['WIN-003']);
  expect(result.checks['M365-002'].parameters).toEqual(snapshot.checks['M365-002'].parameters);
  expect(result.checks['M365-006'].parameters).toEqual(snapshot.checks['M365-006'].parameters);
  expect(result.checks['M365-007']).toEqual(snapshot.checks['M365-007']);
  expect(result.checks['M365-001'].parameters.phoneMethodsAccepted).toBe(false);
  expect(result.checks['M365-003'].parameters.deviceAlternativeAccepted).toBe(false);
  expect(result.checks['M365-003'].assessmentMode).toBe('assessed');
  expect(draft.checks['M365-003'].parameters.deviceAlternativeAccepted).toBe(true);
});

it('restores baseline phone behavior and activates only checks in the template scope', () => {
  const draft = customer();
  draft.activeCheckIds = ['WIN-011'];
  draft.checks['M365-001'].parameters.phoneMethodsAccepted = false;
  const result = applyPolicyTemplate(draft, 'm365-baseline');
  expect(result.checks['M365-001'].parameters.phoneMethodsAccepted).toBe(true);
  expect(result.activeCheckIds).toEqual(['WIN-011', 'M365-001', 'M365-002', 'M365-003', 'M365-004', 'M365-005', 'M365-006']);
});

it('preserves Windows tenant binding, trusted providers, exceptions and server configuration', () => {
  const draft = customer();
  draft.activeCheckIds = ['WIN-011'];
  const result = applyPolicyTemplate(draft, 'windows-baseline');
  for (const key of ['WIN-003', 'WIN-005', 'WIN-008', 'WIN-010', 'M365-001', 'SYS-003'] as const) {
    expect(result.checks[key].parameters).toEqual(draft.checks[key].parameters);
  }
  expect(result.checks['WIN-002'].notApplicableEditionIds).toEqual(['Core']);
  expect(result.activeCheckIds).toContain('WIN-003');
  expect(result.activeCheckIds).toContain('WIN-004');
  expect(result.activeCheckIds).not.toContain('WIN-010');
  expect(result.m365).toEqual(draft.m365);
  expect(result.agent).toEqual(draft.agent);
  expect(applyPolicyTemplate(result, 'windows-baseline')).toEqual(result);
});
