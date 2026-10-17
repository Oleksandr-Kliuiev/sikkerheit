import { Link } from 'react-router';
import { useState } from 'react';
import type { PolicyConfiguration } from '../../api/types';
import { Button, Field, Notice } from '../../components/ui';
import { useI18n } from '../../i18n/i18n';
import { applyPolicyTemplate, POLICY_TEMPLATES, POLICY_TEMPLATE_VERSION, type PolicyTemplateId } from '../../lib/policy-templates';
import { PolicyReview } from './PolicyReview';

export function PolicyTemplates({ configuration, onApply }: {
  configuration: PolicyConfiguration; onApply: (next: PolicyConfiguration) => void;
}) {
  const { t } = useI18n();
  const [template, setTemplate] = useState<PolicyTemplateId>('m365-baseline');
  const [preview, setPreview] = useState<{ before: PolicyConfiguration; after: PolicyConfiguration; name: string } | null>(null);
  const [applied, setApplied] = useState(false);
  return <section className="policy-templates panel" aria-label={t('templates.title')}>
    <h3>{t('templates.title')}</h3>
    <p><Link to="/policy-templates">{t('library.open')}</Link></p>
    <p className="help">{t('templates.help')}</p>
    <div className="form-row">
      <Field label={t('templates.choose')}>{(id) => <select id={id} value={template}
        onChange={(event) => setTemplate(event.target.value as PolicyTemplateId)}>
        {POLICY_TEMPLATES.map((value) => <option key={value} value={value}>{t(`templates.${value}.name`)}</option>)}
      </select>}</Field>
      <Button onClick={() => setPreview({ before: structuredClone(configuration), after: applyPolicyTemplate(configuration, template),
        name: t(`templates.${template}.name`) })}>{t('templates.preview')}</Button>
    </div>
    <p className="help">{t(`templates.${template}.help`)} {t('templates.version', { version: POLICY_TEMPLATE_VERSION })}</p>
    {applied && <Notice>{t('templates.draftApplied')}</Notice>}
    {preview && <PolicyReview before={preview.before} after={preview.after} pending={false} error={null}
      title={t('templates.review', { name: preview.name })} help={t('templates.reviewHelp')} confirmLabel={t('templates.applyDraft')}
      onClose={() => setPreview(null)} onConfirm={() => { onApply(preview.after); setPreview(null); setApplied(true); }} />}
  </section>;
}
