import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { patch, post } from '../api/client';
import { org, useFinding, useFindingEvents, useFindings, useStaff, type FindingFilters } from '../api/hooks';
import type { Finding } from '../api/types';
import { useI18n } from '../i18n/i18n';
import { useAuth } from '../lib/auth';
import { formatDateTime, fromLocalInput, toLocalInput } from '../lib/format';
import { Badge, Button, Dialog, Empty, ErrorMessage, Facts, Field, Loading, Notice, severityTone } from './ui';

const filterValues = {
  technicalState: ['open', 'resolved'],
  severity: ['critical', 'warning'],
  freshness: ['fresh', 'stale'],
  workflowState: ['new', 'in_progress', 'risk_accepted', 'suppressed'],
} as const;

const filterLabels: Record<keyof typeof filterValues, string> = {
  technicalState: 'findings.filterState',
  severity: 'findings.filterSeverity',
  freshness: 'findings.filterFreshness',
  workflowState: 'findings.filterWorkflow',
};

const valuePrefix: Record<keyof typeof filterValues, string> = {
  technicalState: 'technical',
  severity: 'severity',
  freshness: 'freshness',
  workflowState: 'workflow',
};

export function subjectText(finding: Pick<Finding, 'subject'>, t: (key: string) => string): string {
  return finding.subject.type === 'tenant' ? t('subject.tenant') : finding.subject.displayName ?? finding.subject.key;
}

/** Findings of one organization or the shared queue of all (FR-06, FR-09). */
export function FindingsList({ organizationId, organizationNames }: { organizationId: string | null; organizationNames?: Map<string, string> }) {
  const { t, locale, language } = useI18n();
  const [filters, setFilters] = useState<FindingFilters>({ technicalState: ['open'] });
  const [selected, setSelected] = useState<Finding | null>(null);
  const findings = useFindings(organizationId, filters, language);
  const items = findings.data?.pages.flatMap((page) => page.items) ?? [];

  function toggle(name: keyof typeof filterValues, value: string) {
    setFilters((current) => {
      const values = new Set(current[name] ?? []);
      if (values.has(value)) {
        values.delete(value);
      } else {
        values.add(value);
      }
      return { ...current, [name]: [...values] };
    });
  }

  return (
    <>
      <div className="filters" role="group">
        {(Object.keys(filterValues) as (keyof typeof filterValues)[]).map((name) => (
          <fieldset key={name} className="filter">
            <legend>{t(filterLabels[name])}</legend>
            {filterValues[name].map((value) => (
              <label key={value} className="chip">
                <input type="checkbox" checked={filters[name]?.includes(value) ?? false} onChange={() => toggle(name, value)} />
                {t(`${valuePrefix[name]}.${value}`)}
              </label>
            ))}
          </fieldset>
        ))}
      </div>
      {findings.isPending && <Loading />}
      <ErrorMessage error={findings.error} onRetry={() => void findings.refetch()} />
      {findings.data && items.length === 0 && <Empty>{t('findings.empty')}</Empty>}
      {items.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">{t('findings.severity')}</th>
                <th scope="col">{t('findings.check')}</th>
                {organizationNames && <th scope="col">{t('findings.organization')}</th>}
                <th scope="col">{t('findings.subject')}</th>
                <th scope="col">{t('findings.state')}</th>
                <th scope="col">{t('findings.workflow')}</th>
                <th scope="col">{t('findings.opened')}</th>
                <th scope="col">{t('findings.due')}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((finding) => (
                <tr key={finding.id} className="clickable" onClick={() => setSelected(finding)}>
                  <td>
                    <Badge tone={severityTone(finding.severity)}>{t(`severity.${finding.severity}`)}</Badge>
                  </td>
                  <th scope="row">
                    <button type="button" className="link-button" onClick={() => setSelected(finding)}>
                      {finding.title}
                    </button>
                    <span className="id">{finding.checkId}</span>
                  </th>
                  {organizationNames && <td>{organizationNames.get(finding.organizationId) ?? '—'}</td>}
                  <td className="wrap">{subjectText(finding, t)}</td>
                  <td>
                    {t(`technical.${finding.technicalState}`)}
                    {finding.technicalState === 'open' && finding.freshness === 'stale' && (
                      <>
                        {' '}
                        <Badge tone="warn">{t('freshness.stale')}</Badge>
                      </>
                    )}
                  </td>
                  <td>{t(`workflow.${finding.workflowState}`)}</td>
                  <td>{formatDateTime(finding.openedAt, locale)}</td>
                  <td>{formatDateTime(finding.dueAt, locale)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {findings.hasNextPage && (
        <Button busy={findings.isFetchingNextPage} onClick={() => void findings.fetchNextPage()}>
          {t('common.loadMore')}
        </Button>
      )}
      {selected && <FindingDialog organizationId={selected.organizationId} findingId={selected.id} onClose={() => setSelected(null)} />}
    </>
  );
}

function FindingDialog({ organizationId, findingId, onClose }: { organizationId: string; findingId: string; onClose: () => void }) {
  const { t, locale, language } = useI18n();
  const detail = useFinding(organizationId, findingId, language);
  const events = useFindingEvents(organizationId, findingId);
  const finding = detail.data?.finding;
  const translated = detail.data?.contentLanguage === null || detail.data?.contentLanguage === language;
  return (
    <Dialog open onClose={onClose} wide title={finding ? finding.title : t('common.loading')}>
      {detail.isPending && <Loading />}
      <ErrorMessage error={detail.error} />
      {finding && detail.data && (
        <div className="finding">
          {!translated && <Notice>{t('common.translationMissing')}</Notice>}
          <div className="badges">
            <Badge tone={severityTone(finding.severity)}>{t(`severity.${finding.severity}`)}</Badge>
            <Badge tone={finding.technicalState === 'open' ? 'bad' : 'good'}>{t(`technical.${finding.technicalState}`)}</Badge>
            <Badge>{t(`workflow.${finding.workflowState}`)}</Badge>
            <Badge tone={finding.freshness === 'fresh' ? 'neutral' : 'warn'}>{t(`freshness.${finding.freshness}`)}</Badge>
            <span className="id">{finding.checkId}</span>
          </div>
          {finding.technicalState === 'open' && finding.freshness === 'stale' && <Notice tone="warn">{t('finding.staleWarning')}</Notice>}
          <Facts items={[
            [t('findings.subject'), subjectText(finding, t)],
            [t('findings.opened'), formatDateTime(finding.openedAt, locale)],
            [t('findings.observed'), formatDateTime(finding.latestObservedAt, locale)],
          ]} />
          <h3>{t('finding.recommendation')}</h3>
          <p>{finding.recommendation}</p>
          <WorkPanel organizationId={organizationId} finding={finding} etag={detail.data.etag} />
          <DecisionPanel organizationId={organizationId} finding={finding} etag={detail.data.etag} />
          <h3>{t('finding.history')}</h3>
          {events.isPending && <Loading />}
          <ol className="timeline">
            {(events.data ?? []).map((event) => (
              <li key={event.id}>
                <time>{formatDateTime(event.occurredAt, locale)}</time>
                <span>
                  {t(`event.${event.eventType}`)} <span className="muted">({t(`cause.${event.cause}`)})</span>
                  {event.toWorkflowState && <> → {t(`workflow.${event.toWorkflowState}`)}</>}
                </span>
              </li>
            ))}
          </ol>
        </div>
      )}
    </Dialog>
  );
}

function useFindingRefresh(organizationId: string, findingId: string) {
  const client = useQueryClient();
  return async () => {
    await client.invalidateQueries({ queryKey: ['finding', organizationId, findingId] });
    await client.invalidateQueries({ queryKey: ['finding-events', organizationId, findingId] });
    await client.invalidateQueries({ queryKey: ['findings'] });
  };
}

function WorkPanel({ organizationId, finding, etag }: { organizationId: string; finding: Finding; etag: string | null }) {
  const { t } = useI18n();
  const { canWork } = useAuth();
  const staff = useStaff();
  const refresh = useFindingRefresh(organizationId, finding.id);
  const [assigneeId, setAssigneeId] = useState(finding.assigneeId ?? '');
  const [dueAt, setDueAt] = useState(toLocalInput(finding.dueAt));
  const path = `${org(organizationId)}/findings/${finding.id}`;
  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => patch<Finding>(path, body, etag),
    onSuccess: refresh,
  });
  if (!canWork) {
    return null;
  }
  const workers = (staff.data ?? []).filter((member) => member.active && member.roles.some((role) => role !== 'Reader'));
  const decided = finding.workflowState === 'risk_accepted' || finding.workflowState === 'suppressed';
  return (
    <section className="panel">
      <h3>{t('finding.work')}</h3>
      <ErrorMessage error={save.error} />
      <div className="form-row">
        <Field label={t('finding.assignee')}>
          {(id) => (
            <select id={id} value={assigneeId} onChange={(event) => setAssigneeId(event.target.value)}>
              <option value="">{t('finding.noAssignee')}</option>
              {workers.map((member) => (
                <option key={member.entraUserId} value={member.entraUserId}>
                  {member.displayName ?? member.entraUserId}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label={t('finding.dueAt')}>
          {(id) => <input id={id} type="datetime-local" value={dueAt} onChange={(event) => setDueAt(event.target.value)} />}
        </Field>
      </div>
      <div className="button-row">
        <Button busy={save.isPending} onClick={() => save.mutate({ assigneeId: assigneeId || null, dueAt: fromLocalInput(dueAt) })}>
          {t('finding.saveWork')}
        </Button>
        {!decided && finding.workflowState === 'new' && (
          <Button variant="primary" busy={save.isPending} onClick={() => save.mutate({ workflowState: 'in_progress' })}>
            {t('finding.startWork')}
          </Button>
        )}
        {!decided && finding.workflowState === 'in_progress' && (
          <Button busy={save.isPending} onClick={() => save.mutate({ workflowState: 'new' })}>
            {t('finding.backToNew')}
          </Button>
        )}
      </div>
    </section>
  );
}

function DecisionPanel({ organizationId, finding, etag }: { organizationId: string; finding: Finding; etag: string | null }) {
  const { t, locale } = useI18n();
  const { isAdmin } = useAuth();
  const refresh = useFindingRefresh(organizationId, finding.id);
  const [reason, setReason] = useState('');
  const [reviewAt, setReviewAt] = useState('');
  const decide = useMutation({
    mutationFn: (body: Record<string, unknown>) => post<Finding>(`${org(organizationId)}/findings/${finding.id}/risk-decisions`, body, etag),
    onSuccess: async () => {
      setReason('');
      setReviewAt('');
      await refresh();
    },
  });
  const decided = finding.workflowState === 'risk_accepted' || finding.workflowState === 'suppressed';
  if (!decided && (!isAdmin || finding.technicalState !== 'open')) {
    return null;
  }
  return (
    <section className="panel">
      <h3>{t('finding.decision')}</h3>
      {decided && (
        <p>
          <Badge tone="info">{t(`workflow.${finding.workflowState}`)}</Badge>{' '}
          {finding.workflowReason && t('finding.decidedReason', { reason: finding.workflowReason })}{' '}
          {finding.reviewAt && <span className="muted">{t('finding.reviewUntil', { time: formatDateTime(finding.reviewAt, locale) })}</span>}
        </p>
      )}
      {isAdmin && (
        <>
          <ErrorMessage error={decide.error} />
          {finding.technicalState === 'open' && (
            <>
              <p className="help">{t('finding.decisionHelp')}</p>
              <Field label={t('finding.reason')}>
                {(id) => <textarea id={id} value={reason} maxLength={1000} rows={3} onChange={(event) => setReason(event.target.value)} />}
              </Field>
              <Field label={t('finding.reviewAt')}>
                {(id) => <input id={id} type="datetime-local" value={reviewAt} onChange={(event) => setReviewAt(event.target.value)} />}
              </Field>
            </>
          )}
          <div className="button-row">
            {finding.technicalState === 'open' && (['risk_accepted', 'suppressed'] as const).map((decision) => (
              <Button key={decision} busy={decide.isPending} disabled={!reason.trim() || !reviewAt}
                onClick={() => decide.mutate({ decision, reason: reason.trim(), reviewAt: fromLocalInput(reviewAt) })}>
                {t(decision === 'risk_accepted' ? 'finding.accept' : 'finding.suppress')}
              </Button>
            ))}
            {decided && (
              <Button variant="danger" busy={decide.isPending} onClick={() => decide.mutate({ decision: 'withdrawn' })}>
                {t('finding.withdraw')}
              </Button>
            )}
          </div>
        </>
      )}
    </section>
  );
}
