import { NavLink, Outlet, useParams } from 'react-router';
import { useOrganization } from '../../api/hooks';
import { Badge, ErrorMessage, Loading } from '../../components/ui';
import { useI18n } from '../../i18n/i18n';
import { formatDateTime } from '../../lib/format';

export function useOrganizationId(): string {
  const { organizationId } = useParams();
  return organizationId ?? '';
}

export function OrganizationLayout() {
  const { t, locale } = useI18n();
  const id = useOrganizationId();
  const organization = useOrganization(id);
  const tabs = ['overview', 'findings', 'assessments', 'reports', 'policy', 'settings'] as const;
  return (
    <>
      <ErrorMessage error={organization.error} onRetry={() => void organization.refetch()} />
      {organization.isPending && <Loading />}
      {organization.data && (
        <>
          <div className="page-header">
            <div>
              <h1>{organization.data.name}</h1>
              <p className="muted">
                {organization.data.timezone} · {t(`language.${organization.data.reportLanguage}`)}
                {organization.data.status !== 'active' && (
                  <>
                    {' · '}
                    <Badge tone="warn">{t(`orgStatus.${organization.data.status}`)}</Badge>
                  </>
                )}
                {organization.data.deletionDueAt && <> · {t('settings.deletionDue', { time: formatDateTime(organization.data.deletionDueAt, locale) })}</>}
              </p>
            </div>
          </div>
          <nav className="tabs" aria-label={organization.data.name}>
            {tabs.map((tab) => (
              <NavLink key={tab} to={tab === 'overview' ? `/organizations/${id}` : `/organizations/${id}/${tab}`} end>
                {t(`tabs.${tab}`)}
              </NavLink>
            ))}
          </nav>
          <Outlet context={organization.data} />
        </>
      )}
    </>
  );
}
