export interface PolicyChange { path: string[]; before: unknown; after: unknown }

function comparable(value: unknown): string {
  // Policy arrays are sets of identifiers, providers or profiles. Reordering does not change a rule.
  if (Array.isArray(value)) return JSON.stringify(value.map(comparable).sort());
  if (value !== null && typeof value === 'object') {
    return JSON.stringify(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, comparable(item)]));
  }
  return JSON.stringify(value);
}

/** Keep the exact proposed snapshot separate from the editable form until it is confirmed. */
export function policyChanges(before: unknown, after: unknown, path: string[] = []): PolicyChange[] {
  if (comparable(before) === comparable(after)) return [];
  if (before !== null && after !== null && typeof before === 'object' && typeof after === 'object'
    && !Array.isArray(before) && !Array.isArray(after)) {
    const left = before as Record<string, unknown>;
    const right = after as Record<string, unknown>;
    return [...new Set([...Object.keys(left), ...Object.keys(right)])].sort()
      .flatMap((key) => policyChanges(left[key], right[key], [...path, key]));
  }
  return [{ path, before, after }];
}
