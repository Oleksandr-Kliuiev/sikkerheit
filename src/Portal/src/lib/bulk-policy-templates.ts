import { ApiError, request } from '../api/client';
import { org } from '../api/hooks';
import type { PolicyTemplateApplication, PolicyTemplatePreview, PolicyTemplatePreviewItem } from '../api/types';

export interface TemplateApplyResult {
  item: PolicyTemplatePreviewItem;
  outcome: 'applied' | 'failed' | 'unknown' | 'skipped';
  application?: PolicyTemplateApplication;
  error?: unknown;
}
export async function applyTemplatePreview(preview: PolicyTemplatePreview, items = preview.items,
  onResult?: (result: TemplateApplyResult) => void, cancelled: () => boolean = () => false): Promise<TemplateApplyResult[]> {
  const results: TemplateApplyResult[] = [];
  let stop = false;
  for (const item of items.filter((row) => row.status === 'ready')) {
    let result: TemplateApplyResult;
    if (stop || cancelled()) result = { item, outcome: 'skipped' };
    else {
      try {
        if (!item.previewToken || !item.policyVersion) throw new ApiError(400, 'validation_failed');
        const application = (await request<PolicyTemplateApplication>(`${org(item.organizationId)}/policy-template-applications`, {
          method: 'POST', body: { templateId: preview.templateId, templateRevision: preview.templateRevision, previewToken: item.previewToken },
          ifMatch: `"${item.policyVersion}"`,
        })).data;
        result = { item, outcome: 'applied', application };
      } catch (error) {
        const unknown = !(error instanceof ApiError) || error.status === 0 || error.status >= 500;
        result = { item, outcome: unknown ? 'unknown' : 'failed', error };
        // A changed template/policy must be reviewed again. Unknown results can be confirmed with the identical token.
        stop = unknown || (error instanceof ApiError && [400, 401, 403, 412, 422, 429].includes(error.status));
      }
    }
    results.push(result);
    onResult?.(result);
  }
  return results;
}
