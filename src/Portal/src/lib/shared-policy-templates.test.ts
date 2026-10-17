import { expect, it } from 'vitest';
import type { PolicyConfiguration } from '../api/types';
import defaults from './policy-defaults.g.json';
import { extractTemplateContent, mergeTemplateContent } from './shared-policy-templates';

it('removes every customer-specific field from portable content and keeps source objects untouched', () => {
  const customer = structuredClone(defaults) as PolicyConfiguration;
  customer.m365.excludedUserIds = ['11111111-1111-4111-8111-111111111111'];
  customer.checks['WIN-010'].parameters.expectedTenantId = '22222222-2222-4222-8222-222222222222';
  customer.checks['WIN-003'].parameters.approvedProviders = ['Private AV'];
  customer.checks['WIN-005'].parameters.approvedFirewallProviders = ['Private FW'];
  customer.checks['M365-006'].parameters.allowedPermissionGrantPolicies = ['Private consent'];
  customer.checks['WIN-008'].parameters.allowedSids = ['S-1-5-21-1-2-3-1001'];
  const original = structuredClone(customer);
  const content = extractTemplateContent(customer, 'all');
  const text = JSON.stringify(content);
  for (const protectedValue of ['11111111', '22222222', 'Private', 'S-1-5-21', 'collectionHourLocal', 'agent', 'WIN-010', 'notApplicableEditionIds']) {
    expect(text).not.toContain(protectedValue);
  }
  expect(content.checks).not.toHaveProperty('M365-007');
  expect(content.checks).toHaveProperty('SYS-003');
  expect(customer).toEqual(original);
  expect(mergeTemplateContent(customer, content)).toEqual(customer);
});

it('changes only the selected scope, preserves identities, and supports inactive checks', () => {
  const customer = structuredClone(defaults) as PolicyConfiguration;
  customer.checks['WIN-003'].parameters = { approvedProviders: ['Custom'], defenderApproved: false };
  const content = extractTemplateContent(customer, 'windows');
  if (content.scope !== 'windows') throw new Error('scope');
  content.checks['WIN-001'].parameters.warnFreePercent = 30;
  content.activeCheckIds = content.activeCheckIds.filter((id) => id !== 'WIN-006');
  const result = mergeTemplateContent(customer, content);
  expect(result.checks['WIN-001'].parameters.warnFreePercent).toBe(30);
  expect(result.checks['WIN-003'].parameters).toEqual(customer.checks['WIN-003'].parameters);
  expect(result.checks['M365-001']).toEqual(customer.checks['M365-001']);
  expect(result.activeCheckIds).not.toContain('WIN-006');
  expect(result.activeCheckIds).toContain('M365-001');
  expect(result.activeCheckIds).toContain('WIN-011');
});
