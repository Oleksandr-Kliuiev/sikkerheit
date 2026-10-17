import type { PolicyConfiguration } from '../api/types';
import generatedDefaults from './policy-defaults.g.json';

// Generated from the schema. Customer-specific inputs are preserved by the allowlisted merge below.
const defaults = generatedDefaults as PolicyConfiguration;
export const POLICY_TEMPLATES = ['m365-baseline', 'm365-stronger-mfa', 'windows-baseline'] as const;
export type PolicyTemplateId = typeof POLICY_TEMPLATES[number];
export const POLICY_TEMPLATE_VERSION = 1;

/** Apply a versioned, scoped preset to a cloned draft. Never copies customer identities or changes scheduling. */
export function applyPolicyTemplate(current: PolicyConfiguration, template: PolicyTemplateId): PolicyConfiguration {
  const result = structuredClone(current);
  const checkIds = (Object.keys(result.checks) as (keyof PolicyConfiguration['checks'])[]).filter((id) =>
    template.startsWith('m365-') ? id.startsWith('M365-') && id !== 'M365-007'
      : id.startsWith('WIN-') && id !== 'WIN-010');
  for (const id of checkIds) {
    // The assignment is safe for each check's schema: both objects come from the same generated key.
    Object.assign(result.checks[id], structuredClone(defaults.checks[id]));
    if (!result.activeCheckIds.includes(id as PolicyConfiguration['activeCheckIds'][number])) {
      result.activeCheckIds.push(id as PolicyConfiguration['activeCheckIds'][number]);
    }
  }
  if (template.startsWith('m365-')) {
    result.checks['M365-002'].parameters.privilegedRoleTemplateIds = structuredClone(current.checks['M365-002'].parameters.privilegedRoleTemplateIds);
    result.checks['M365-006'].parameters.allowedPermissionGrantPolicies = structuredClone(current.checks['M365-006'].parameters.allowedPermissionGrantPolicies);
    if (template === 'm365-stronger-mfa') result.checks['M365-001'].parameters.phoneMethodsAccepted = false;
  } else {
    result.checks['WIN-003'].parameters = structuredClone(current.checks['WIN-003'].parameters);
    result.checks['WIN-005'].parameters.approvedFirewallProviders = structuredClone(current.checks['WIN-005'].parameters.approvedFirewallProviders);
    result.checks['WIN-008'].parameters.allowedSids = structuredClone(current.checks['WIN-008'].parameters.allowedSids);
    result.checks['WIN-008'].parameters.allowedDomainRids = structuredClone(current.checks['WIN-008'].parameters.allowedDomainRids);
    for (const id of checkIds) {
      const target = result.checks[id];
      const source = current.checks[id];
      if ('notApplicableEditionIds' in target && 'notApplicableEditionIds' in source) {
        target.notApplicableEditionIds = structuredClone(source.notApplicableEditionIds);
      }
    }
    // The preset cannot invent a trusted antivirus provider. Retain informational mode until inputs exist.
    const av = result.checks['WIN-003'].parameters;
    if (!av.defenderApproved && av.approvedProviders.length === 0) result.checks['WIN-003'].assessmentMode = 'informational';
  }
  return result;
}
