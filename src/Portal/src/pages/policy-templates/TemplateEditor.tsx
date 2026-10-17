import { useMutation } from '@tanstack/react-query';
import { useState } from 'react';
import { get, post } from '../../api/client';
import { org, useOrganizations } from '../../api/hooks';
import type { Page, PolicyConfiguration, PolicyRevision, PolicyTemplate, PolicyTemplateContent } from '../../api/types';
import { Button, Dialog, ErrorMessage, Field, Notice } from '../../components/ui';
import { useI18n } from '../../i18n/i18n';
import defaults from '../../lib/policy-defaults.g.json';
import { extractTemplateContent, mergeTemplateContent, templateScopes, type TemplateScope } from '../../lib/shared-policy-templates';
import { PolicyChangesTable } from '../organization/PolicyReview';
import { TemplateFields } from './TemplateFields';

type Proposal = { name: string; description: string; archived: boolean; content: PolicyTemplateContent };
export function TemplateEditor({ template, onClose, onSaved }: {
  template?: PolicyTemplate; onClose: () => void; onSaved: (saved: PolicyTemplate) => void;
}) {
  const { t } = useI18n();
  const organizations = useOrganizations();
  const baseline = defaults as PolicyConfiguration;
  const before = template ? mergeTemplateContent(baseline, template.content) : baseline;
  const [configuration, setConfiguration] = useState(() => structuredClone(before));
  const [name, setName] = useState(template?.name ?? '');
  const [description, setDescription] = useState(template?.description ?? '');
  const [scope, setScope] = useState<TemplateScope>(template?.content.scope ?? 'm365');
  const [archived, setArchived] = useState(template?.archived ?? false);
  const [source, setSource] = useState('');
  const [proposal, setProposal] = useState<Proposal | null>(null);
  const copy = useMutation({ mutationFn: async () => {
    const page = await get<Page<PolicyRevision>>(`${org(source)}/policy-revisions?limit=1`);
    if (!page.items[0]) throw new Error('missing policy');
    return page.items[0].configuration;
  }, onSuccess: setConfiguration });
  const save = useMutation({ mutationFn: (next: Proposal) => template
    ? post<PolicyTemplate>(`/api/v1/policy-templates/${template.id}/revisions`, next, `"${template.revision}"`)
    : post<PolicyTemplate>('/api/v1/policy-templates', { name: next.name, description: next.description, content: next.content }),
  onSuccess: onSaved });
  return <section className="card template-editor">
    <h2>{t(template ? 'library.edit' : 'library.new')}</h2>
    <Notice>{t('library.portableHelp')}</Notice>
    <form onSubmit={(event) => { event.preventDefault(); save.reset(); setProposal({ name: name.trim(), description: description.trim(),
      archived, content: extractTemplateContent(configuration, scope) }); }}>
      <fieldset disabled={save.isPending || copy.isPending}>
        <div className="template-fields">
          <Field label={t('library.name')}>{(id) => <input id={id} maxLength={80} required value={name} onChange={(event) => setName(event.target.value)} />}</Field>
          <Field label={t('library.scope')}>{(id) => <select id={id} value={scope} onChange={(event) => setScope(event.target.value as TemplateScope)}>
            {templateScopes.map((value) => <option key={value} value={value}>{t(`library.scope.${value}`)}</option>)}
          </select>}</Field>
        </div>
        <Field label={t('library.description')}>{(id) => <textarea id={id} maxLength={500} rows={3} value={description} onChange={(event) => setDescription(event.target.value)} />}</Field>
        <div className="form-row">
          <Field label={t('library.source')}>{(id) => <select id={id} value={source} onChange={(event) => setSource(event.target.value)}>
            <option value="">{t('common.choose')}</option>{(organizations.data ?? []).map(({ organization }) => <option key={organization.id} value={organization.id}>{organization.name}</option>)}
          </select>}</Field>
          <Button disabled={!source} busy={copy.isPending} onClick={() => copy.mutate()}>{t('library.copySource')}</Button>
        </div>
        <ErrorMessage error={copy.error ?? organizations.error} />
        <TemplateFields configuration={configuration} scope={scope} onChange={setConfiguration} />
        {template && <label className="check"><input type="checkbox" checked={archived} onChange={(event) => setArchived(event.target.checked)} />{t('library.archived')}</label>}
        <div className="button-row"><Button onClick={onClose}>{t('common.cancel')}</Button>
          <Button type="submit" variant="primary" disabled={!name.trim()}>{t('library.reviewSave')}</Button></div>
      </fieldset>
    </form>
    {proposal && <Dialog open wide title={t('library.reviewSave')} onClose={() => { if (!save.isPending) setProposal(null); }} footer={<>
      <Button disabled={save.isPending} onClick={() => setProposal(null)}>{t('common.cancel')}</Button>
      <Button variant="primary" busy={save.isPending} onClick={() => save.mutate(proposal)}>{t('library.confirmSave')}</Button>
    </>}>
      <ErrorMessage error={save.error} /><Notice>{t('library.libraryOnly')}</Notice>
      <dl className="facts"><div><dt>{t('library.name')}</dt><dd>{proposal.name}</dd></div>
        <div><dt>{t('library.description')}</dt><dd>{proposal.description || t('common.none')}</dd></div>
        <div><dt>{t('library.scope')}</dt><dd>{t(`library.scope.${proposal.content.scope}`)}</dd></div>
        <div><dt>{t('library.archived')}</dt><dd>{t(proposal.archived ? 'common.yes' : 'common.no')}</dd></div></dl>
      <PolicyChangesTable before={before} after={mergeTemplateContent(before, proposal.content)} />
    </Dialog>}
  </section>;
}
