import type { PolicyConfiguration, PolicyTemplateContent } from '../api/types';
import metadata from './policy-template-fields.g.json';

export type TemplateScope = PolicyTemplateContent['scope'];
type CheckId = keyof PolicyConfiguration['checks'];
export const templateScopes: TemplateScope[] = ['m365', 'windows', 'all'];
export function templateCheckIds(scope: TemplateScope): CheckId[] { return metadata.scopes[scope] as CheckId[]; }

/** The API validates the same portable allowlist. No organization identifiers, schedules or exceptions enter a template. */
export function extractTemplateContent(configuration: PolicyConfiguration, scope: TemplateScope): PolicyTemplateContent {
  const ids = templateCheckIds(scope);
  const checks = Object.fromEntries(ids.map((id) => {
    const check = configuration.checks[id];
    const protectedNames = (metadata.protectedParameters as Record<string, string[]>)[id] ?? [];
    return [id, { assessmentMode: check.assessmentMode, freshnessWindowHours: check.freshnessWindowHours,
      parameters: Object.fromEntries(Object.entries(check.parameters).filter(([name]) => !protectedNames.includes(name))) }];
  }));
  return structuredClone({ scope, activeCheckIds: configuration.activeCheckIds.filter((id) => ids.includes(id)), checks }) as PolicyTemplateContent;
}

/** Used for editing/review only; the server recomputes and validates every real application. */
export function mergeTemplateContent(configuration: PolicyConfiguration, content: PolicyTemplateContent): PolicyConfiguration {
  const result = structuredClone(configuration);
  const ids = templateCheckIds(content.scope);
  const selected = new Set<string>(content.activeCheckIds);
  const active = result.activeCheckIds.filter((id) => !ids.includes(id) || selected.has(id));
  for (const id of content.activeCheckIds) if (!active.includes(id)) active.push(id);
  result.activeCheckIds = active;
  for (const [id, check] of Object.entries(content.checks)) {
    const target = result.checks[id as CheckId];
    target.assessmentMode = check.assessmentMode;
    target.freshnessWindowHours = check.freshnessWindowHours;
    Object.assign(target.parameters, structuredClone(check.parameters));
  }
  return result;
}
