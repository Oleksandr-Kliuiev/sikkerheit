import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useStaff } from '../api/hooks';
import type { Finding } from '../api/types';
import { useI18n } from '../i18n/i18n';
import { applyFindingWork, BULK_FINDING_LIMIT, findingKey, prepareFindingWork, type FindingWorkPlan, type FindingWorkResult, type WorkChange } from '../lib/bulk-finding-work';
import { formatDateTime, fromLocalInput } from '../lib/format';
import { Button, Dialog, ErrorMessage, Field, Notice } from './ui';

export function BulkFindingWork({ selected, organizationNames, onClear }: {
  selected: Finding[]; organizationNames?: Map<string, string>; onClear: () => void;
}) {
  const { t, locale } = useI18n();
  const staff = useStaff();
  const client = useQueryClient();
  const [assignee, setAssignee] = useState('keep');
  const [dueMode, setDueMode] = useState('keep');
  const [dueAt, setDueAt] = useState('');
  const [plans, setPlans] = useState<FindingWorkPlan[] | null>(null);
  const [results, setResults] = useState<FindingWorkResult[] | null>(null);
  const preview = useMutation({ retry: false, mutationFn: (change: WorkChange) => prepareFindingWork(selected, change), onSuccess: setPlans });
  const apply = useMutation({
    retry: false, mutationFn: applyFindingWork,
    onSuccess: async (result) => {
      setResults(result);
      await Promise.all([
        client.invalidateQueries({ queryKey: ['findings'] }), client.invalidateQueries({ queryKey: ['finding'] }),
        client.invalidateQueries({ queryKey: ['finding-events'] }),
      ]);
    },
  });
  const busy = preview.isPending || apply.isPending;
  const workers = (staff.data ?? []).filter((person) => person.active && person.roles.some((role) => role === 'Admin' || role === 'Technician'));
  function close() {
    if (busy) return;
    setPlans(null); setResults(null); apply.reset(); preview.reset(); onClear();
  }
  function assigneeName(id: string | null | undefined) {
    return id ? workers.find((person) => person.entraUserId === id)?.displayName ?? id : t('finding.noAssignee');
  }
  return <>
    {selected.length > 0 && <section className="panel" aria-label={t('bulk.title')}>
      <p>{t('bulk.selected', { count: selected.length, limit: BULK_FINDING_LIMIT })}</p>
      <ErrorMessage error={preview.error ?? staff.error} />
      <form onSubmit={(event) => {
        event.preventDefault();
        const change: WorkChange = {};
        if (assignee !== 'keep') change.assigneeId = assignee === 'clear' ? null : assignee;
        if (dueMode !== 'keep') change.dueAt = dueMode === 'clear' ? null : fromLocalInput(dueAt);
        preview.mutate(change);
      }}>
        <div className="form-row">
          <Field label={t('finding.assignee')}>{(id) => <select id={id} value={assignee} disabled={busy || staff.isPending}
            onChange={(event) => setAssignee(event.target.value)}>
            <option value="keep">{t('bulk.keep')}</option><option value="clear">{t('finding.noAssignee')}</option>
            {workers.map((person) => <option key={person.entraUserId} value={person.entraUserId}>{person.displayName ?? person.entraUserId}</option>)}
          </select>}</Field>
          <Field label={t('finding.dueAt')}>{(id) => <select id={id} value={dueMode} disabled={busy} onChange={(event) => setDueMode(event.target.value)}>
            <option value="keep">{t('bulk.keep')}</option><option value="set">{t('bulk.setDue')}</option><option value="clear">{t('bulk.clearDue')}</option>
          </select>}</Field>
          {dueMode === 'set' && <Field label={t('bulk.newDue')}>{(id) => <input id={id} type="datetime-local" required value={dueAt}
            disabled={busy} onChange={(event) => setDueAt(event.target.value)} />}</Field>}
        </div>
        <div className="button-row">
          <Button type="submit" busy={preview.isPending} disabled={busy || (assignee === 'keep' && dueMode === 'keep') || selected.length > BULK_FINDING_LIMIT}>
            {t('bulk.review')}
          </Button><Button disabled={busy} onClick={onClear}>{t('bulk.clearSelection')}</Button>
        </div>
      </form>
    </section>}
    {plans && <Dialog open wide title={t('bulk.reviewTitle')} onClose={close} footer={<>
      <Button disabled={busy} onClick={close}>{t(results ? 'common.close' : 'common.cancel')}</Button>
      {!results && <Button variant="primary" busy={apply.isPending} disabled={plans.length === 0} onClick={() => apply.mutate(plans)}>
        {t('bulk.apply', { count: plans.length })}
      </Button>}
    </>}>
      <ErrorMessage error={apply.error} />
      <Notice>{t(results ? 'bulk.resultHelp' : plans.length ? 'bulk.reviewHelp' : 'bulk.noChanges')}</Notice>
      <div className="table-wrap"><table className="table compact">
        <thead><tr><th scope="col">{t('findings.organization')}</th><th scope="col">{t('findings.check')}</th>
          <th scope="col">{t('policy.before')}</th><th scope="col">{t('policy.after')}</th>{results && <th scope="col">{t('bulk.result')}</th>}</tr></thead>
        <tbody>{plans.map((plan) => {
          const result = results?.find((item) => findingKey(item.finding) === findingKey(plan.finding));
          return <tr key={findingKey(plan.finding)}>
            <td>{organizationNames?.get(plan.finding.organizationId) ?? plan.finding.organizationId}</td>
            <th scope="row">{plan.finding.title}<span className="id">{plan.finding.id}</span></th>
            <td>{'assigneeId' in plan.change && <p>{assigneeName(plan.finding.assigneeId)}</p>}
              {'dueAt' in plan.change && <p>{formatDateTime(plan.finding.dueAt, locale)}</p>}</td>
            <td>{'assigneeId' in plan.change && <p>{assigneeName(plan.change.assigneeId)}</p>}
              {'dueAt' in plan.change && <p>{formatDateTime(plan.change.dueAt, locale)}</p>}</td>
            {result && <td>{t(`bulk.${result.outcome}`)}<ErrorMessage error={result.error} /></td>}
          </tr>;
        })}</tbody>
      </table></div>
    </Dialog>}
  </>;
}
