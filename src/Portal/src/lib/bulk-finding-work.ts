import { ApiError, patch, request } from '../api/client';
import { org } from '../api/hooks';
import type { Finding } from '../api/types';

export const BULK_FINDING_LIMIT = 50;
export type WorkChange = { assigneeId?: string | null; dueAt?: string | null };
export interface FindingWorkPlan { finding: Finding; etag: string; change: WorkChange }
export interface FindingWorkResult { finding: Finding; outcome: 'applied' | 'failed' | 'unknown' | 'skipped'; error?: unknown }
export const findingKey = (finding: Pick<Finding, 'id' | 'organizationId'>) => `${finding.organizationId}:${finding.id}`;
export const canBulkWork = (finding: Finding) => finding.technicalState === 'open'
  && (finding.workflowState === 'new' || finding.workflowState === 'in_progress');
const path = (finding: Finding) => `${org(finding.organizationId)}/findings/${encodeURIComponent(finding.id)}`;

/** Refresh every row before review. An unreadable or no longer actionable row aborts the whole preview. */
export async function prepareFindingWork(selected: Finding[], proposed: WorkChange): Promise<FindingWorkPlan[]> {
  const unique = [...new Map(selected.map((finding) => [findingKey(finding), finding])).values()];
  if (unique.length === 0 || unique.length > BULK_FINDING_LIMIT) throw new ApiError(400, 'validation_failed');
  const plans: FindingWorkPlan[] = [];
  for (const selectedFinding of unique) {
    const current = await request<Finding>(path(selectedFinding));
    const finding = current.data;
    if (findingKey(finding) !== findingKey(selectedFinding) || !canBulkWork(finding) || !current.etag) {
      throw new ApiError(409, 'workflow_transition_forbidden');
    }
    const change: WorkChange = {};
    if ('assigneeId' in proposed && proposed.assigneeId !== finding.assigneeId) change.assigneeId = proposed.assigneeId;
    const sameDue = proposed.dueAt === finding.dueAt || (proposed.dueAt && finding.dueAt
      && Date.parse(proposed.dueAt) === Date.parse(finding.dueAt));
    if ('dueAt' in proposed && !sameDue) change.dueAt = proposed.dueAt;
    if (Object.keys(change).length > 0) plans.push({ finding, etag: current.etag, change });
  }
  return plans;
}

/** Per-row optimistic concurrency and audit stay on the existing API. Never retry an ambiguous mutation. */
export async function applyFindingWork(plans: FindingWorkPlan[]): Promise<FindingWorkResult[]> {
  if (plans.length > BULK_FINDING_LIMIT) throw new ApiError(400, 'validation_failed');
  const results: FindingWorkResult[] = [];
  let stopped = false;
  for (const plan of plans) {
    if (stopped) { results.push({ finding: plan.finding, outcome: 'skipped' }); continue; }
    try {
      await patch<Finding>(path(plan.finding), plan.change, plan.etag);
      results.push({ finding: plan.finding, outcome: 'applied' });
    } catch (error) {
      const ambiguous = !(error instanceof ApiError) || error.status === 0 || error.status >= 500;
      results.push({ finding: plan.finding, outcome: ambiguous ? 'unknown' : 'failed', error });
      stopped = ambiguous || (error instanceof ApiError && (error.status === 401 || error.status === 403 || error.status === 429));
    }
  }
  return results;
}
