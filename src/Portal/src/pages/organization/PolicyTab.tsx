import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { post } from '../../api/client';
import { org, usePolicyRevisions } from '../../api/hooks';
import type { PolicyConfiguration, PolicyRevision } from '../../api/types';
import { Button, ErrorMessage, Field, Loading, Notice, Section } from '../../components/ui';
import { useI18n } from '../../i18n/i18n';
import { useAuth } from '../../lib/auth';
import { formatDateTime } from '../../lib/format';
import { useOrganizationId } from './OrganizationLayout';
import { WindowsPolicyFields } from './WindowsPolicyFields';
import { PolicyReview } from './PolicyReview';
import { PolicyTemplates } from './PolicyTemplates';
import policyFields from '../../lib/policy-template-fields.g.json';

type Checks = PolicyConfiguration['checks'];

export function PolicyTab() {
  const { t } = useI18n();
  const id = useOrganizationId();
  const revisions = usePolicyRevisions(id);
  const [saved, setSaved] = useState<number | null>(null);
  const current = revisions.data?.items[0];
  return (
    <>
      {revisions.isPending && <Loading />}
      <ErrorMessage error={revisions.error} />
      {saved !== null && <Notice tone="good">{t('policy.saved', { version: saved })}</Notice>}
      {current && <PolicyEditor key={current.version} revision={current} onSaved={setSaved} />}
    </>
  );
}

function lines(value: string): string[] {
  return value.split('\n').map((line) => line.trim()).filter(Boolean);
}

/** Every save is a new policy revision (FR-03), including the Windows and server checks. */
function PolicyEditor({ revision, onSaved }: { revision: PolicyRevision; onSaved: (version: number) => void }) {
  const { t, locale } = useI18n();
  const { isAdmin } = useAuth();
  const id = useOrganizationId();
  const client = useQueryClient();
  const [config, setConfig] = useState<PolicyConfiguration>(() => structuredClone(revision.configuration));
  const [excluded, setExcluded] = useState(revision.configuration.m365.excludedUserIds.join('\n'));
  const [allowedConsent, setAllowedConsent] = useState(
    revision.configuration.checks['M365-006'].parameters.allowedPermissionGrantPolicies.join('\n'));
  const [proposed, setProposed] = useState<PolicyConfiguration | null>(null);
  const save = useMutation({
    mutationFn: (next: PolicyConfiguration) => post<PolicyRevision>(`${org(id)}/policy-revisions`, { configuration: next }, `"${revision.version}"`),
    onSuccess: async (created) => {
      setProposed(null);
      onSaved(created.version);
      await client.invalidateQueries({ queryKey: ['policies', id] });
    },
  });

  function update(change: (draft: PolicyConfiguration) => void) {
    setConfig((current) => {
      const next = structuredClone(current);
      change(next);
      return next;
    });
  }

  function setCheck<K extends keyof Checks>(checkId: K, change: (check: Checks[K]) => void) {
    update((draft) => change(draft.checks[checkId]));
  }

  const active = new Set<string>(config.activeCheckIds);
  const disabled = !isAdmin;
  return (
    <Section title={t('policy.version', { version: revision.version })} id="policy-title"
      actions={<span className="muted">{t('policy.effectiveFrom', { time: formatDateTime(revision.effectiveFrom, locale) })}</span>}>
      {!isAdmin && <Notice>{t('policy.readOnly')}</Notice>}
      <ErrorMessage error={save.error} />
      {isAdmin && <PolicyTemplates configuration={{ ...config, m365: { ...config.m365, excludedUserIds: lines(excluded) },
        checks: { ...config.checks, 'M365-006': { ...config.checks['M365-006'], parameters: { allowedPermissionGrantPolicies: lines(allowedConsent) } } } }}
        onApply={(next) => { setConfig(next); setProposed(null); save.reset(); }} />}
      <form className="policy-form" onSubmit={(event) => {
        event.preventDefault();
        if (!isAdmin) return;
        const next = structuredClone(config);
        next.m365.excludedUserIds = lines(excluded);
        next.checks['M365-006'].parameters.allowedPermissionGrantPolicies = lines(allowedConsent);
        save.reset();
        setProposed(next);
      }}>
      <fieldset className="form-grid" disabled={disabled}>
        <legend>{t('policy.m365')}</legend>
        <Field label={t('policy.collectionHour')}>
          {(fieldId) => (
            <input id={fieldId} type="number" min={0} max={23} value={config.m365.collectionHourLocal}
              onChange={(event) => update((draft) => { draft.m365.collectionHourLocal = Number(event.target.value); })} />
          )}
        </Field>
        <Field label={t('policy.minAdmins')}>
          {(fieldId) => (
            <input id={fieldId} type="number" min={0} max={10} value={config.checks['M365-005'].parameters.minGlobalAdmins}
              onChange={(event) => setCheck('M365-005', (check) => { check.parameters.minGlobalAdmins = Number(event.target.value); })} />
          )}
        </Field>
        <Field label={t('policy.maxAdmins')}>
          {(fieldId) => (
            <input id={fieldId} type="number" min={1} max={20} value={config.checks['M365-005'].parameters.maxGlobalAdmins}
              onChange={(event) => setCheck('M365-005', (check) => { check.parameters.maxGlobalAdmins = Number(event.target.value); })} />
          )}
        </Field>
        <Field label={t('policy.excludedUsers')} help={t('policy.excludedUsersHelp')}>
          {(fieldId) => <textarea id={fieldId} rows={3} value={excluded} onChange={(event) => setExcluded(event.target.value)} />}
        </Field>
        <Field label={t('policy.allowedConsent')}>
          {(fieldId) => <textarea id={fieldId} rows={3} value={allowedConsent} onChange={(event) => setAllowedConsent(event.target.value)} />}
        </Field>
        <div className="checks">
          <label className="check">
            <input type="checkbox" checked={config.checks['M365-001'].parameters.phoneMethodsAccepted}
              onChange={(event) => setCheck('M365-001', (check) => { check.parameters.phoneMethodsAccepted = event.target.checked; })} />
            {t('policy.phoneAccepted')}
          </label>
          <label className="check">
            <input type="checkbox" checked={config.checks['M365-003'].parameters.deviceAlternativeAccepted}
              onChange={(event) => setCheck('M365-003', (check) => { check.parameters.deviceAlternativeAccepted = event.target.checked; })} />
            {t('policy.deviceAlternative')}
          </label>
          <label className="check">
            <input type="checkbox" checked={config.checks['M365-003'].parameters.trustedLocationsExclusionAccepted}
              onChange={(event) => setCheck('M365-003', (check) => { check.parameters.trustedLocationsExclusionAccepted = event.target.checked; })} />
            {t('policy.trustedLocations')}
          </label>
        </div>
      </fieldset>
      <fieldset className="form-grid" disabled={disabled}>
        <legend>{t('policy.checks')}</legend>
        <div className="table-wrap">
          <table className="table compact">
            <thead>
              <tr>
                <th scope="col">{t('findings.check')}</th>
                <th scope="col">{t('policy.active')}</th>
                <th scope="col">{t('policy.mode')}</th>
                <th scope="col">{t('policy.freshness')}</th>
              </tr>
            </thead>
            <tbody>
              {(Object.keys(config.checks) as (keyof Checks)[]).map((checkId) => (
                <tr key={checkId}>
                  <th scope="row">
                    {t(`check.${checkId}`)} <span className="id">{checkId}</span>
                  </th>
                  <td>
                    {checkId.startsWith('SYS-') ? t('policy.serverCheck') : <input type="checkbox"
                      disabled={checkId === 'WIN-011'} aria-label={`${t('policy.active')} ${checkId}`} checked={active.has(checkId)}
                      onChange={(event) => update((draft) => {
                        draft.activeCheckIds = (event.target.checked
                          ? [...draft.activeCheckIds, checkId]
                          : draft.activeCheckIds.filter((value) => value !== checkId)) as PolicyConfiguration['activeCheckIds'];
                      })} />}
                  </td>
                  <td>
                    <select aria-label={`${t('policy.mode')} ${checkId}`} value={config.checks[checkId].assessmentMode}
                      disabled={policyFields.constraints[checkId].modes.length === 1}
                      onChange={(event) => setCheck(checkId, (check) => {
                        check.assessmentMode = event.target.value as 'assessed' | 'informational';
                      })}>
                      {policyFields.constraints[checkId].modes.map((mode) => <option key={mode} value={mode}>
                        {t(mode === 'assessed' ? 'policy.modeAssessed' : 'policy.modeInformational')}
                      </option>)}
                    </select>
                  </td>
                  <td>
                    <input type="number" min={1} max={720} aria-label={`${t('policy.freshness')} ${checkId}`}
                      value={config.checks[checkId].freshnessWindowHours}
                      onChange={(event) => setCheck(checkId, (check) => { check.freshnessWindowHours = Number(event.target.value); })} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="help">{t('policy.windowsNote')}</p>
      </fieldset>
      <WindowsPolicyFields configuration={config} disabled={disabled} update={update} />
      {isAdmin && (
        <div className="button-row">
          <Button variant="primary" type="submit" busy={save.isPending}>
            {t('policy.save')}
          </Button>
        </div>
      )}
      </form>
      {isAdmin && proposed && <PolicyReview before={revision.configuration} after={proposed} pending={save.isPending} error={save.error}
        onClose={() => setProposed(null)} onConfirm={() => save.mutate(proposed)} />}
    </Section>
  );
}
