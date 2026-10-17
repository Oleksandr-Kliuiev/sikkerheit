import { useState } from 'react';
import type { PolicyConfiguration } from '../../api/types';
import { Field } from '../../components/ui';
import { useI18n } from '../../i18n/i18n';

type CheckId = keyof PolicyConfiguration['checks'];
type Group = 'agent' | CheckId;
type Spec = { group: Group; name: string; kind: 'number' | 'boolean' | 'list' | 'rids' | 'uuid'; min?: number; max?: number };
const specs: Spec[] = [
  { group: 'agent', name: 'scanIntervalHours', kind: 'number', min: 1, max: 168 },
  { group: 'agent', name: 'checkInIntervalHours', kind: 'number', min: 1, max: 24 },
  { group: 'agent', name: 'scanJitterMinutes', kind: 'number', min: 0, max: 60 },
  { group: 'agent', name: 'maxBufferDays', kind: 'number', min: 1, max: 30 },
  { group: 'agent', name: 'maxBatchAgeDays', kind: 'number', min: 2, max: 32 },
  { group: 'WIN-001', name: 'warnFreePercent', kind: 'number', min: 0, max: 100 },
  { group: 'WIN-001', name: 'criticalFreePercent', kind: 'number', min: 0, max: 100 },
  { group: 'WIN-001', name: 'warnFreeBytes', kind: 'number', min: 0 },
  { group: 'WIN-001', name: 'criticalFreeBytes', kind: 'number', min: 0 },
  { group: 'WIN-002', name: 'encryptionRequired', kind: 'boolean' },
  { group: 'WIN-003', name: 'approvedProviders', kind: 'list', max: 50 },
  { group: 'WIN-003', name: 'defenderApproved', kind: 'boolean' },
  { group: 'WIN-004', name: 'warnDays', kind: 'number', min: 1 },
  { group: 'WIN-004', name: 'criticalDays', kind: 'number', min: 1 },
  { group: 'WIN-005', name: 'approvedFirewallProviders', kind: 'list', max: 20 },
  { group: 'WIN-006', name: 'maxSearchAgeDays', kind: 'number', min: 1, max: 60 },
  { group: 'WIN-007', name: 'warnDays', kind: 'number', min: 1, max: 60 },
  { group: 'WIN-008', name: 'allowBuiltinAdministrator', kind: 'boolean' },
  { group: 'WIN-008', name: 'allowedDomainRids', kind: 'rids', max: 20 },
  { group: 'WIN-008', name: 'allowedSids', kind: 'list', max: 100 },
  { group: 'WIN-008', name: 'maxOtherLocalAccounts', kind: 'number', min: 0, max: 10 },
  { group: 'WIN-009', name: 'secureBootRequired', kind: 'boolean' },
  { group: 'WIN-010', name: 'expectedTenantId', kind: 'uuid' },
  { group: 'SYS-003', name: 'graceDays', kind: 'number', min: 0, max: 60 },
  { group: 'SYS-003', name: 'criticalBehindMonths', kind: 'number', min: 2, max: 12 },
];

function ListParameter({ id, value, spec, onChange }: { id: string; value: unknown[]; spec: Spec; onChange: (value: unknown[]) => void }) {
  const { t } = useI18n();
  const [text, setText] = useState(value.join('\n'));
  return <textarea id={id} rows={3} value={text}
    onChange={(event) => {
      const raw = event.target.value;
      setText(raw);
      const items = raw.split('\n').map((line) => line.trim()).filter(Boolean);
      const valid = items.length <= (spec.max ?? 100) && new Set(items).size === items.length
        && items.every((item) => spec.kind === 'rids' ? /^\d+$/.test(item) && Number.isSafeInteger(Number(item)) && Number(item) >= 500
          : spec.name === 'allowedSids' ? /^S-1-\d+(-\d+)+$/.test(item) : item.length <= 120);
      event.target.setCustomValidity(valid ? '' : t('policy.invalidList'));
      if (valid) onChange(spec.kind === 'rids' ? items.map(Number) : items);
    }} />;
}

/** All Windows thresholds and agent scheduling; the API still enforces cross-field constraints. */
export function WindowsPolicyFields({ configuration, disabled, update }: {
  configuration: PolicyConfiguration;
  disabled: boolean;
  update: (change: (draft: PolicyConfiguration) => void) => void;
}) {
  const { t } = useI18n();
  const groups = [...new Set(specs.map((spec) => spec.group))];
  return <>
    {groups.map((group) => <fieldset key={group} className="form-grid" disabled={disabled}>
      <legend>{group === 'agent' ? t('policy.agent') : `${t(`check.${group}`)} (${group})`}</legend>
      {specs.filter((spec) => spec.group === group).map((spec) => {
        const parameters = (group === 'agent' ? configuration.agent : configuration.checks[group].parameters) as unknown as Record<string, unknown>;
        const value = parameters[spec.name];
        const change = (next: unknown) => update((draft) => {
          Object.assign(group === 'agent' ? draft.agent : draft.checks[group].parameters, { [spec.name]: next });
        });
        if (spec.kind === 'boolean') return <label className="check" key={spec.name}>
          <input type="checkbox" checked={Boolean(value)} onChange={(event) => change(event.target.checked)} />
          {t(`policy.param.${spec.name}`)}
        </label>;
        return <Field key={spec.name} label={t(`policy.param.${spec.name}`)}>
          {(fieldId) => spec.kind === 'list' || spec.kind === 'rids'
              ? <ListParameter id={fieldId} value={value as unknown[]} spec={spec} onChange={change} />
              : spec.kind === 'uuid'
                ? <input id={fieldId} value={(value as string | null) ?? ''} pattern="[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"
                  onChange={(event) => change(event.target.value.trim() || null)} />
                : <input id={fieldId} type="number" required min={spec.min} max={spec.max} step={1} value={value as number}
                  onChange={(event) => change(Number(event.target.value))} />}
        </Field>;
      })}
      {group === 'WIN-005' && <div className="checks">
        <p>{t('policy.param.requiredProfiles')}</p>
        {(['domain', 'private', 'public'] as const).map((profile) => <label key={profile} className="check">
          <input type="checkbox" checked={configuration.checks['WIN-005'].parameters.requiredProfiles.includes(profile)}
            onChange={(event) => update((draft) => {
              const profiles = draft.checks['WIN-005'].parameters.requiredProfiles;
              draft.checks['WIN-005'].parameters.requiredProfiles = event.target.checked
                ? [...profiles, profile] : profiles.filter((value) => value !== profile);
            })} />{t(`policy.profile.${profile}`)}
        </label>)}
      </div>}
    </fieldset>)}
  </>;
}
