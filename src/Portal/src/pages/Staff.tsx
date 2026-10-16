import { useStaff } from '../api/hooks';
import { Badge, ErrorMessage, Loading } from '../components/ui';
import { useI18n } from '../i18n/i18n';
import { formatDateTime } from '../lib/format';

export function StaffPage() {
  const { t, locale } = useI18n();
  const staff = useStaff();
  return (
    <>
      <div className="page-header">
        <div>
          <h1>{t('staff.title')}</h1>
          <p className="muted">{t('staff.lead')}</p>
        </div>
      </div>
      {staff.isPending && <Loading />}
      <ErrorMessage error={staff.error} onRetry={() => void staff.refetch()} />
      {staff.data && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">{t('staff.name')}</th>
                <th scope="col">{t('staff.roles')}</th>
                <th scope="col">{t('staff.lastSignIn')}</th>
                <th scope="col">{t('staff.status')}</th>
              </tr>
            </thead>
            <tbody>
              {staff.data.map((member) => (
                <tr key={member.entraUserId}>
                  <th scope="row">{member.displayName ?? member.entraUserId}</th>
                  <td>{member.roles.map((role) => t(`role.${role}`)).join(', ')}</td>
                  <td>{formatDateTime(member.lastSignInAt, locale)}</td>
                  <td>
                    <Badge tone={member.active ? 'good' : 'neutral'}>{t(member.active ? 'staff.active' : 'staff.inactive')}</Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
