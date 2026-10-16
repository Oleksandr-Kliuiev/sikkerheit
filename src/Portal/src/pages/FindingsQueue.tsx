import { useMemo } from 'react';
import { useOrganizations } from '../api/hooks';
import { FindingsList } from '../components/Findings';
import { useI18n } from '../i18n/i18n';

/** The shared queue of all customers (FR-09). */
export function FindingsQueuePage() {
  const { t } = useI18n();
  const organizations = useOrganizations();
  const names = useMemo(
    () => new Map((organizations.data ?? []).map((item) => [item.organization.id, item.organization.name])),
    [organizations.data],
  );
  return (
    <>
      <div className="page-header">
        <h1>{t('findings.queueTitle')}</h1>
      </div>
      <FindingsList organizationId={null} organizationNames={names} />
    </>
  );
}
