import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router';
import { usePolicyTemplateHistory, usePolicyTemplates, useStaff } from '../../api/hooks';
import type { PolicyTemplate } from '../../api/types';
import { Badge, Button, Empty, ErrorMessage, Loading, Notice } from '../../components/ui';
import { useI18n } from '../../i18n/i18n';
import { useAuth } from '../../lib/auth';
import { formatDateTime } from '../../lib/format';
import defaults from '../../lib/policy-defaults.g.json';
import type { PolicyConfiguration } from '../../api/types';
import { mergeTemplateContent } from '../../lib/shared-policy-templates';
import { TemplateFields } from './TemplateFields';
import { BulkPolicyTemplate } from './BulkPolicyTemplate';
import { TemplateEditor } from './TemplateEditor';

export function PolicyTemplateLibrary() {
  const { t, locale } = useI18n();
  const { isAdmin } = useAuth();
  const client = useQueryClient();
  const [includeArchived, setIncludeArchived] = useState(false);
  const templates = usePolicyTemplates(includeArchived);
  const rows = templates.data?.pages.flatMap((page) => page.items) ?? [];
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [creating, setCreating] = useState(false);
  const [applying, setApplying] = useState(false);
  const [saved, setSaved] = useState(false);
  const selected = rows.find((row) => row.id === selectedId);
  async function onSaved(template: PolicyTemplate) {
    setSelectedId(template.id); setCreating(false); setEditing(false); setApplying(false); setSaved(true);
    if (template.archived) setIncludeArchived(true);
    await client.invalidateQueries({ queryKey: ['policy-templates'] });
    await client.invalidateQueries({ queryKey: ['policy-template-history', template.id] });
  }
  return <>
    <div className="page-header"><h1>{t('library.title')}</h1>{isAdmin && <Button variant="primary" onClick={() => {
      setCreating(true); setEditing(false); setApplying(false); setSaved(false);
    }}>{t('library.new')}</Button>}</div>
    <p className="help">{t('library.intro')}</p>
    {saved && <Notice tone="good">{t('library.saved')}</Notice>}
    {!isAdmin && <Notice>{t('library.readOnly')}</Notice>}
    <ErrorMessage error={templates.error} />
    <div className="template-library">
      <aside className="card">
        <label className="check"><input type="checkbox" checked={includeArchived} onChange={(event) => setIncludeArchived(event.target.checked)} />{t('library.includeArchived')}</label>
        {templates.isPending && <Loading />}
        {!templates.isPending && rows.length === 0 && <Empty>{t('library.empty')}</Empty>}
        <div className="template-list">{rows.map((row) => <Button key={row.id} aria-pressed={row.id === selectedId} onClick={() => {
          setSelectedId(row.id); setCreating(false); setEditing(false); setApplying(false); setSaved(false);
        }}>{row.name} · {t('library.version', { version: row.revision })} {row.archived && t('library.archived')}</Button>)}</div>
        {templates.hasNextPage && <Button busy={templates.isFetchingNextPage} onClick={() => void templates.fetchNextPage()}>{t('common.loadMore')}</Button>}
      </aside>
      <div className="template-content stack">
        {isAdmin && (creating || (editing && selected)) ? <TemplateEditor key={creating ? 'new' : `${selected!.id}:${selected!.revision}`}
          template={creating ? undefined : selected} onClose={() => { setCreating(false); setEditing(false); }} onSaved={(value) => void onSaved(value)} />
          : selected && <section className="card">
            <h2>{selected.name}</h2><p className="wrap">{selected.description}</p>
            <p>{t(`library.scope.${selected.content.scope}`)} · {t('library.version', { version: selected.revision })} · {formatDateTime(selected.createdAt, locale)}</p>
            {selected.archived && <Notice>{t('library.archivedHelp')}</Notice>}
            {isAdmin && <div className="button-row"><Button onClick={() => { setEditing(true); setApplying(false); }}>{t('library.edit')}</Button>
              <Button variant="primary" disabled={selected.archived} onClick={() => setApplying(true)}>{t('library.bulkAction')}</Button></div>}
            <details className="template-history"><summary>{t('library.settings')}</summary>
              <fieldset disabled><TemplateFields configuration={mergeTemplateContent(defaults as PolicyConfiguration, selected.content)}
                scope={selected.content.scope} onChange={() => {}} /></fieldset>
            </details>
            <TemplateHistory template={selected} />
          </section>}
        {isAdmin && applying && selected && !creating && !editing && <BulkPolicyTemplate key={`${selected.id}:${selected.revision}`} template={selected} onClose={() => setApplying(false)} />}
        {!selected && !creating && <Notice>{t('library.chooseHelp')} <Link to="/organizations">{t('nav.organizations')}</Link></Notice>}
      </div>
    </div>
  </>;
}

function TemplateHistory({ template }: { template: PolicyTemplate }) {
  const { t, locale } = useI18n();
  const [inspected, setInspected] = useState<PolicyTemplate | null>(null);
  const history = usePolicyTemplateHistory(template.id);
  const staff = useStaff();
  const names = new Map((staff.data ?? []).map((person) => [person.entraUserId, person.displayName]));
  return <details className="template-history"><summary>{t('library.history')}</summary>
    <ErrorMessage error={history.error} />
    {(history.data?.pages.flatMap((page) => page.items) ?? []).map((row) => <article key={row.revision}>
      <h3>{t('library.version', { version: row.revision })} <Badge>{row.archived ? t('library.archived') : t(`library.scope.${row.content.scope}`)}</Badge></h3>
      <p>{row.name} · {formatDateTime(row.createdAt, locale)} · {names.get(row.createdBy) ?? t('common.unknown')}</p>
      <p className="wrap">{row.description}</p><Button onClick={() => setInspected(row)}>{t('library.inspect', { version: row.revision })}</Button>
    </article>)}
    {inspected?.id === template.id && <section><h3>{t('library.version', { version: inspected.revision })}</h3>
      <fieldset disabled><TemplateFields configuration={mergeTemplateContent(defaults as PolicyConfiguration, inspected.content)}
        scope={inspected.content.scope} onChange={() => {}} /></fieldset></section>}
    {history.hasNextPage && <Button busy={history.isFetchingNextPage} onClick={() => void history.fetchNextPage()}>{t('common.loadMore')}</Button>}
  </details>;
}
