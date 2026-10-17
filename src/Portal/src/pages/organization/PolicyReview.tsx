import type { PolicyConfiguration } from '../../api/types';
import { Button, Dialog, ErrorMessage, Notice } from '../../components/ui';
import { useI18n } from '../../i18n/i18n';
import { policyChanges } from '../../lib/policy-changes';

const labels: Record<string, string> = {
  activeCheckIds: 'checks', collectionHourLocal: 'collectionHour', excludedUserIds: 'excludedUsers',
  minGlobalAdmins: 'minAdmins', maxGlobalAdmins: 'maxAdmins', allowedPermissionGrantPolicies: 'allowedConsent',
  phoneMethodsAccepted: 'phoneAccepted', deviceAlternativeAccepted: 'deviceAlternative',
  trustedLocationsExclusionAccepted: 'trustedLocations', freshnessWindowHours: 'freshness', assessmentMode: 'mode',
};

export function PolicyReview({ before, after, pending, error, onClose, onConfirm, title, help, confirmLabel }: {
  before: PolicyConfiguration; after: PolicyConfiguration; pending: boolean; error: unknown;
  title?: string; help?: string; confirmLabel?: string;
  onClose: () => void; onConfirm: () => void;
}) {
  const { t } = useI18n();
  const changes = policyChanges(before, after);
  return <Dialog open wide title={title ?? t('policy.reviewTitle')} onClose={() => { if (!pending) onClose(); }}
    footer={<>
      <Button disabled={pending} onClick={onClose}>{t('common.cancel')}</Button>
      <Button variant="primary" busy={pending} disabled={changes.length === 0} onClick={onConfirm}>{confirmLabel ?? t('policy.applyChanges')}</Button>
    </>}>
    <ErrorMessage error={error} />
    <Notice>{changes.length === 0 ? t('policy.noChanges') : help ?? t('policy.reviewHelp')}</Notice>
    <PolicyChangesTable before={before} after={after} />
  </Dialog>;
}

export function PolicyChangesTable({ before, after }: { before: PolicyConfiguration; after: PolicyConfiguration }) {
  const { t } = useI18n();
  const changes = policyChanges(before, after);
  function label(path: string[]) {
    const name = path.at(-1)!;
    const field = t(labels[name] ? `policy.${labels[name]}` : `policy.param.${name}`);
    return path[0] === 'checks' ? `${t(`check.${path[1]}`)} (${path[1]}) — ${field}` : field;
  }
  function value(item: unknown): string {
    if (typeof item === 'boolean') return t(item ? 'common.yes' : 'common.no');
    if (item === null || item === undefined || (Array.isArray(item) && item.length === 0)) return t('common.none');
    if (Array.isArray(item)) return item.map(value).join(', ');
    if (item === 'assessed' || item === 'informational') return t(item === 'assessed' ? 'policy.modeAssessed' : 'policy.modeInformational');
    return String(item);
  }
  return changes.length > 0 ? <div className="table-wrap policy-review"><table className="table compact">
      <thead><tr><th scope="col">{t('policy.changedSetting')}</th><th scope="col">{t('policy.before')}</th><th scope="col">{t('policy.after')}</th></tr></thead>
      <tbody>{changes.map((change) => <tr key={change.path.join('.')}>
        <th scope="row">{label(change.path)}</th><td className="wrap" data-label={t('policy.before')}>{value(change.before)}</td><td className="wrap" data-label={t('policy.after')}>{value(change.after)}</td>
      </tr>)}</tbody>
    </table></div> : null;
}
