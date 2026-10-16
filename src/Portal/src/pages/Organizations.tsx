import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { post } from '../api/client';
import { useOrganizations } from '../api/hooks';
import type { Organization } from '../api/types';
import { Badge, Button, Dialog, Empty, ErrorMessage, Field, Loading } from '../components/ui';
import { useI18n, type Language } from '../i18n/i18n';
import { useAuth } from '../lib/auth';
import { formatDateTime, formatPercent } from '../lib/format';

export function connectionTone(status: string) {
  return status === 'active' ? 'good' : status === 'consent_pending' ? 'info' : status === 'disconnected' ? 'bad' : 'neutral';
}

export function OrganizationsPage() {
  const { t, locale } = useI18n();
  const { isAdmin } = useAuth();
  const organizations = useOrganizations();
  const [creating, setCreating] = useState(false);
  const items = organizations.data ?? [];
  const critical = items.reduce((sum, item) => sum + item.openCritical, 0);

  return (
    <>
      <div className="page-header">
        <div>
          <h1>{t('orgs.title')}</h1>
          {organizations.data && <p className="muted">{t('orgs.summary', { count: items.length, critical })}</p>}
        </div>
        {isAdmin && (
          <Button variant="primary" onClick={() => setCreating(true)}>
            {t('orgs.create')}
          </Button>
        )}
      </div>
      {organizations.isPending && <Loading />}
      <ErrorMessage error={organizations.error} onRetry={() => void organizations.refetch()} />
      {organizations.data && items.length === 0 && <Empty>{t('orgs.empty')}</Empty>}
      {items.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">{t('orgs.name')}</th>
                <th scope="col">{t('orgs.m365')}</th>
                <th scope="col" className="num">{t('orgs.openCritical')}</th>
                <th scope="col" className="num">{t('orgs.openWarning')}</th>
                <th scope="col" className="num">{t('orgs.coverage')}</th>
                <th scope="col">{t('orgs.lastCollected')}</th>
              </tr>
            </thead>
            <tbody>
              {items.map(({ organization, m365Status, openCritical, openWarning, coverageAt, lastCollectedAt }) => (
                <tr key={organization.id}>
                  <th scope="row">
                    <Link to={`/organizations/${organization.id}`}>{organization.name}</Link>
                    {organization.status !== 'active' && (
                      <>
                        {' '}
                        <Badge tone="warn">{t(`orgStatus.${organization.status}`)}</Badge>
                      </>
                    )}
                  </th>
                  <td>
                    <Badge tone={connectionTone(m365Status)}>{t(`connection.status.${m365Status}`)}</Badge>
                  </td>
                  <td className="num">{openCritical > 0 ? <Badge tone="bad">{openCritical}</Badge> : 0}</td>
                  <td className="num">{openWarning}</td>
                  <td className="num">{formatPercent(coverageAt, locale, t('common.noData'))}</td>
                  <td>{formatDateTime(lastCollectedAt, locale)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <CreateOrganizationDialog open={creating} onClose={() => setCreating(false)} />
    </>
  );
}

const zones = ['Europe/Oslo', 'Europe/Stockholm', 'Europe/Copenhagen', 'Europe/Helsinki', 'Europe/London', 'UTC'];

function CreateOrganizationDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useI18n();
  const client = useQueryClient();
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [timezone, setTimezone] = useState('Europe/Oslo');
  const [reportLanguage, setReportLanguage] = useState<Language>('nb');
  const create = useMutation({
    mutationFn: () => post<Organization>('/api/v1/organizations', { name: name.trim(), timezone, reportLanguage }),
    onSuccess: async (organization) => {
      await client.invalidateQueries({ queryKey: ['organizations'] });
      onClose();
      setName('');
      void navigate(`/organizations/${organization.id}`);
    },
  });
  return (
    <Dialog open={open} onClose={onClose} title={t('orgs.create')}
      footer={
        <>
          <Button onClick={onClose}>{t('common.cancel')}</Button>
          <Button variant="primary" busy={create.isPending} disabled={name.trim().length === 0} onClick={() => create.mutate()}>
            {t('common.create')}
          </Button>
        </>
      }>
      <ErrorMessage error={create.error} />
      <Field label={t('orgs.name')}>
        {(id) => <input id={id} value={name} maxLength={120} required onChange={(event) => setName(event.target.value)} />}
      </Field>
      <Field label={t('orgs.timezone')}>
        {(id) => (
          <select id={id} value={timezone} onChange={(event) => setTimezone(event.target.value)}>
            {zones.map((zone) => (
              <option key={zone}>{zone}</option>
            ))}
          </select>
        )}
      </Field>
      <Field label={t('orgs.reportLanguage')}>
        {(id) => (
          <select id={id} value={reportLanguage} onChange={(event) => setReportLanguage(event.target.value as Language)}>
            {(['nb', 'nn', 'en'] as const).map((value) => (
              <option key={value} value={value}>
                {t(`language.${value}`)}
              </option>
            ))}
          </select>
        )}
      </Field>
    </Dialog>
  );
}
