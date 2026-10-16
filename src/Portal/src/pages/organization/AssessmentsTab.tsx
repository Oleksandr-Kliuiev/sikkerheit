import { useState } from 'react';
import { useAssessments } from '../../api/hooks';
import { subjectText } from '../../components/Findings';
import { Badge, Button, Empty, ErrorMessage, Loading, resultTone } from '../../components/ui';
import { useI18n } from '../../i18n/i18n';
import { formatDateTime } from '../../lib/format';
import { useOrganizationId } from './OrganizationLayout';

export function AssessmentsTab() {
  const { t, locale, language } = useI18n();
  const id = useOrganizationId();
  const [scope, setScope] = useState<'current' | 'all'>('current');
  const assessments = useAssessments(id, scope, language);
  const items = assessments.data?.pages.flatMap((page) => page.items) ?? [];
  return (
    <>
      <div className="segmented" role="group">
        {(['current', 'all'] as const).map((value) => (
          <Button key={value} variant={scope === value ? 'primary' : 'secondary'} aria-pressed={scope === value} onClick={() => setScope(value)}>
            {t(value === 'current' ? 'assessments.scopeCurrent' : 'assessments.scopeAll')}
          </Button>
        ))}
      </div>
      {assessments.isPending && <Loading />}
      <ErrorMessage error={assessments.error} onRetry={() => void assessments.refetch()} />
      {assessments.data && items.length === 0 && <Empty>{t('assessments.empty')}</Empty>}
      {items.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">{t('findings.check')}</th>
                <th scope="col">{t('findings.subject')}</th>
                <th scope="col">{t('assessments.result')}</th>
                <th scope="col">{t('assessments.explanation')}</th>
                <th scope="col">{t('assessments.observedAt')}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((assessment) => (
                <tr key={assessment.id}>
                  <th scope="row">
                    {t(`check.${assessment.checkId}`)}
                    <span className="id">{assessment.checkId}</span>
                  </th>
                  <td className="wrap">{subjectText(assessment, t)}</td>
                  <td>
                    {assessment.assessmentMode === 'informational' ? (
                      <Badge>{t('result.informational')}</Badge>
                    ) : (
                      <Badge tone={resultTone(assessment.result)}>{t(`result.${assessment.result ?? 'unknown'}`)}</Badge>
                    )}
                    {assessment.severity && <span className="muted"> · {t(`severity.${assessment.severity}`)}</span>}
                    {assessment.freshness === 'stale' && assessment.result !== null && (
                      <>
                        {' '}
                        <Badge tone="warn">{t('freshness.stale')}</Badge>
                      </>
                    )}
                    {assessment.reasonCode && <div className="muted small">{t(`reason.${assessment.reasonCode}`)}</div>}
                  </td>
                  <td className="wrap">
                    {assessment.explanation}
                    {assessment.evidenceAvailability === 'expired' && <div className="muted small">{t('assessments.evidenceExpired')}</div>}
                  </td>
                  <td>
                    {formatDateTime(assessment.observedAt, locale)}
                    <div className="muted small">{t('policy.version', { version: assessment.evaluatedPolicyVersion })}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {assessments.hasNextPage && (
        <Button busy={assessments.isFetchingNextPage} onClick={() => void assessments.fetchNextPage()}>
          {t('common.loadMore')}
        </Button>
      )}
    </>
  );
}
