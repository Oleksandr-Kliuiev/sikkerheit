import type { FindingFilters } from '../api/hooks';

export interface SavedFindingView { name: string; filters: FindingFilters }
const values: Record<string, readonly string[]> = {
  technicalState: ['open', 'resolved'], severity: ['critical', 'warning'], freshness: ['fresh', 'stale'],
  workflowState: ['new', 'in_progress', 'risk_accepted', 'suppressed'],
};

/** Browser storage is untrusted. Persist only bounded filter preferences, never finding data or query cursors. */
export function readFindingViews(raw: string | null): SavedFindingView[] {
  if (!raw || raw.length > 10000) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.slice(0, 8).filter((view): view is SavedFindingView => {
      if (!view || typeof view !== 'object' || typeof view.name !== 'string' || !view.name.trim() || view.name.length > 40
        || !view.filters || typeof view.filters !== 'object' || Array.isArray(view.filters)) return false;
      return Object.entries(view.filters).every(([key, selected]) => {
        if (key === 'assignedTo') return selected === 'me';
        if (key === 'overdue') return selected === 'true';
        return Array.isArray(selected) && selected.length <= 25
          && selected.every((value) => typeof value === 'string' && (key === 'checkId'
            ? /^(M365-00[1-7]|WIN-(00[1-9]|01[01])|SYS-00[1-3])$/.test(value)
            : Object.hasOwn(values, key) && values[key]?.includes(value)));
      });
    });
  } catch { return []; }
}
