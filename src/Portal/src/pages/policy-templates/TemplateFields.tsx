import metadata from '../../lib/policy-template-fields.g.json';
import type { PolicyConfiguration } from '../../api/types';
import { Field } from '../../components/ui';
import { useI18n } from '../../i18n/i18n';
import { extractTemplateContent, templateCheckIds, type TemplateScope } from '../../lib/shared-policy-templates';

const labels: Record<string, string> = { phoneMethodsAccepted: 'phoneAccepted', deviceAlternativeAccepted: 'deviceAlternative',
  trustedLocationsExclusionAccepted: 'trustedLocations', minGlobalAdmins: 'minAdmins', maxGlobalAdmins: 'maxAdmins' };
export function TemplateFields({ configuration, scope, onChange }: {
  configuration: PolicyConfiguration; scope: TemplateScope; onChange: (next: PolicyConfiguration) => void;
}) {
  const { t } = useI18n();
  const portable = extractTemplateContent(configuration, scope);
  function update(change: (draft: PolicyConfiguration) => void) { const draft = structuredClone(configuration); change(draft); onChange(draft); }
  return <div className="template-checks">{templateCheckIds(scope).map((id) => <details key={id} className="template-check">
    <summary>{t(`check.${id}`)} <span className="muted">({id})</span></summary>
    <div className="template-fields">
      {!id.startsWith('SYS-') && <label className="check"><input type="checkbox" disabled={id === 'WIN-011'}
        checked={configuration.activeCheckIds.includes(id as PolicyConfiguration['activeCheckIds'][number])}
        onChange={(event) => update((draft) => {
          draft.activeCheckIds = (event.target.checked ? [...draft.activeCheckIds, id]
            : draft.activeCheckIds.filter((value) => value !== id)) as PolicyConfiguration['activeCheckIds'];
        })} />{t('policy.active')}</label>}
      <Field label={t('policy.mode')}>{(fieldId) => <select id={fieldId} value={configuration.checks[id].assessmentMode}
        onChange={(event) => update((draft) => { draft.checks[id].assessmentMode = event.target.value as 'assessed' | 'informational'; })}>
        {(metadata.constraints as Record<string, { modes: string[] }>)[id]!.modes.map((mode) => <option key={mode} value={mode}>{t(mode === 'assessed' ? 'policy.modeAssessed' : 'policy.modeInformational')}</option>)}
      </select>}</Field>
      <Field label={t('policy.freshness')}>{(fieldId) => <input id={fieldId} type="number" min={1} max={720} required
        value={configuration.checks[id].freshnessWindowHours}
        onChange={(event) => update((draft) => { draft.checks[id].freshnessWindowHours = Number(event.target.value); })} />}</Field>
      {Object.entries((portable.checks as Record<string, { parameters: Record<string, unknown> }>)[id]!.parameters).map(([name, value]) => {
        const label = t(labels[name] ? `policy.${labels[name]}` : `policy.param.${name}`);
        function set(next: unknown) { update((draft) => Object.assign(draft.checks[id].parameters, { [name]: next })); }
        if (typeof value === 'boolean') return <label className="check" key={name}><input type="checkbox" checked={value}
          onChange={(event) => set(event.target.checked)} />{label}</label>;
        if (Array.isArray(value)) return <fieldset key={name}><legend>{label}</legend>{['domain', 'private', 'public'].map((profile) => <label className="check" key={profile}>
          <input type="checkbox" checked={value.includes(profile)} onChange={(event) => set(event.target.checked
            ? [...value, profile] : value.filter((entry) => entry !== profile))} />{t(`policy.profile.${profile}`)}</label>)}</fieldset>;
        const bounds = (metadata.constraints as Record<string, { parameters: Record<string, { minimum?: number; maximum?: number }> }>)[id]!.parameters[name];
        return <Field key={name} label={label}>{(fieldId) => <input id={fieldId} type="number" required min={bounds?.minimum} max={bounds?.maximum} step={1} value={value as number}
          onChange={(event) => set(Number(event.target.value))} />}</Field>;
      })}
    </div>
  </details>)}</div>;
}
