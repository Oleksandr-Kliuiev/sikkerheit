import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { post } from '../../api/client';
import { useOrganizations } from '../../api/hooks';
import type { PolicyTemplate, PolicyTemplatePreview } from '../../api/types';
import { Badge, Button, ErrorMessage, Notice } from '../../components/ui';
import { useI18n } from '../../i18n/i18n';
import { applyTemplatePreview, type TemplateApplyResult } from '../../lib/bulk-policy-templates';
import { formatDateTime } from '../../lib/format';
import { useNow } from '../../lib/use-now';
import { PolicyChangesTable } from '../organization/PolicyReview';

export function BulkPolicyTemplate({ template, onClose }: { template: PolicyTemplate; onClose: () => void }) {
  const { t, locale } = useI18n();
  const organizations = useOrganizations();
  const client = useQueryClient();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [proposal, setProposal] = useState<PolicyTemplatePreview | null>(null);
  const [results, setResults] = useState<TemplateApplyResult[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const now = useNow();
  const preview = useMutation({ mutationFn: () => post<PolicyTemplatePreview>(`/api/v1/policy-templates/${template.id}/preview`,
    { organizationIds: [...selected].sort() }, `"${template.revision}"`), onSuccess: (data) => { setProposal(data); setResults([]); } });
  const ready = proposal?.items.filter((item) => item.status === 'ready') ?? [];
  const expired = proposal ? Date.parse(proposal.expiresAt) <= now : false;
  async function apply(only?: TemplateApplyResult) {
    if (!proposal || busy) return;
    setBusy(true); setError(null);
    try {
      const next = await applyTemplatePreview(proposal, only ? [only.item] : proposal.items, (result) => {
        if (mounted.current) setResults((current) => [...current.filter((row) => row.item.organizationId !== result.item.organizationId), result]);
      }, () => !mounted.current);
      if (next.some((row) => row.outcome === 'applied')) {
        await client.invalidateQueries({ queryKey: ['policies'] });
        await client.invalidateQueries({ queryKey: ['findings'] });
        await client.invalidateQueries({ queryKey: ['organizations'] });
      }
    } catch (failure) { if (mounted.current) setError(failure); }
    finally { if (mounted.current) setBusy(false); }
  }
  return <section className="card template-bulk">
    <h2>{t('library.bulkTitle', { name: template.name, version: template.revision })}</h2>
    <Notice>{t('library.bulkHelp')}</Notice>
    <ErrorMessage error={organizations.error ?? preview.error ?? error} />
    <fieldset disabled={busy || preview.isPending}>
      <p>{t('library.selected', { count: selected.size })}</p>
      <div className="template-client-list">{(organizations.data ?? []).filter(({ organization }) => organization.status === 'active').map(({ organization }) => <label key={organization.id} className="check">
        <input type="checkbox" checked={selected.has(organization.id)} disabled={!selected.has(organization.id) && selected.size >= 50}
          onChange={(event) => {
            const next = new Set(selected);
            if (event.target.checked) next.add(organization.id); else next.delete(organization.id);
            setSelected(next); setProposal(null); setResults([]); preview.reset();
          }} />{organization.name}
      </label>)}</div>
      <div className="button-row"><Button onClick={onClose}>{t('common.cancel')}</Button>
        <Button disabled={selected.size === 0} busy={preview.isPending} onClick={() => { setProposal(null); setResults([]); preview.mutate(); }}>{t('library.previewClients')}</Button></div>
    </fieldset>
    {proposal && <>
      <p>{t('library.previewExpires', { time: formatDateTime(proposal.expiresAt, locale) })}</p>
      {expired && <Notice tone="warn">{t('library.expired')}</Notice>}
      <div className="template-preview-list">{proposal.items.map((item) => {
        const result = results.find((row) => row.item.organizationId === item.organizationId);
        return <details key={item.organizationId} className="template-check" open={item.status === 'ready' || !!result}>
          <summary>{item.organizationName ?? t('library.unavailableClient')} <Badge tone={result?.outcome === 'applied' ? 'good' : item.status === 'unavailable' || result?.outcome === 'failed' || result?.outcome === 'unknown' ? 'warn' : 'neutral'}>
            {t(`library.status.${result?.outcome ?? item.status}`)}</Badge></summary>
          {item.problemCode && <Notice tone="warn">{t(`problem.${item.problemCode}`)}</Notice>}
          {item.before && item.after && item.status === 'ready' && <PolicyChangesTable before={item.before} after={item.after} />}
          {result?.application && <p>{t('library.appliedVersion', { version: result.application.policyVersion })}</p>}
          <ErrorMessage error={result?.error} />
          {result?.outcome === 'unknown' && <><Notice tone="warn">{t('library.unknownHelp')}</Notice>
            <Button disabled={busy} onClick={() => void apply(result)}>{t('library.confirmUnknown')}</Button></>}
        </details>;
      })}</div>
      {results.length === 0 && <Button variant="primary" busy={busy} disabled={ready.length === 0 || expired} onClick={() => void apply()}>
        {t('library.applyClients', { count: ready.length })}</Button>}
      {results.length > 0 && <Notice>{t(busy ? 'library.applying' : 'library.finished')}</Notice>}
    </>}
  </section>;
}
