import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { useOutletContext } from 'react-router';
import { post } from '../../api/client';
import { org, useReports } from '../../api/hooks';
import type { Organization, Report } from '../../api/types';
import { Badge, Button, Empty, ErrorMessage, Field, Loading, Notice, Section } from '../../components/ui';
import { useI18n } from '../../i18n/i18n';
import { useAuth } from '../../lib/auth';
import { formatDate } from '../../lib/format';
import { completedWeeks } from '../../lib/weeks';
import { useOrganizationId } from './OrganizationLayout';

export function ReportsTab() {
  const { t, locale } = useI18n();
  const { canWork } = useAuth();
  const id = useOrganizationId();
  const organization = useOutletContext<Organization>();
  const client = useQueryClient();
  const reports = useReports(id);
  const weeks = useMemo(() => completedWeeks(organization.timezone, new Date(), 8), [organization.timezone]);
  const [week, setWeek] = useState(0);
  const [queued, setQueued] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () => {
      const selected = weeks[week]!;
      return post<Report>(`${org(id)}/reports`, { periodStart: selected.periodStart, periodEnd: selected.periodEnd, format: 'html' });
    },
    onSuccess: async () => {
      const selected = weeks[week]!;
      setQueued(t('reports.weekLabel', { week: selected.week, year: selected.year }));
      await client.invalidateQueries({ queryKey: ['reports', id] });
    },
  });
  return (
    <Section title={t('reports.title')} id="reports-title">
      <p className="muted">{t('reports.lead')}</p>
      {canWork && organization.status === 'active' && (
        <div className="form-row align-end">
          <Field label={t('reports.week')}>
            {(fieldId) => (
              <select id={fieldId} value={week} onChange={(event) => setWeek(Number(event.target.value))}>
                {weeks.map((item, index) => (
                  <option key={item.periodStart} value={index}>
                    {t('reports.weekLabel', { week: item.week, year: item.year })}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <Button variant="primary" busy={create.isPending} onClick={() => create.mutate()}>
            {t('reports.create')}
          </Button>
        </div>
      )}
      <ErrorMessage error={create.error} />
      {queued && <Notice tone="good">{t('reports.queued', { week: queued })}</Notice>}
      {reports.isPending && <Loading />}
      <ErrorMessage error={reports.error} />
      {reports.data && reports.data.items.length === 0 && <Empty>{t('reports.empty')}</Empty>}
      {reports.data && reports.data.items.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">{t('reports.period')}</th>
                <th scope="col">{t('reports.language')}</th>
                <th scope="col">{t('reports.state')}</th>
                <th scope="col">
                  <span className="visually-hidden">{t('common.actions')}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {reports.data.items.map((report) => (
                <tr key={report.id}>
                  <td>
                    {formatDate(report.periodStart, locale)} – {formatDate(new Date(new Date(report.periodEnd).getTime() - 1).toISOString(), locale)}
                  </td>
                  <td>{t(`language.${report.language}`)}</td>
                  <td>
                    <Badge tone={report.state === 'ready' ? 'good' : report.state === 'failed' ? 'bad' : 'info'}>
                      {t(`reportState.${report.state}`)}
                    </Badge>
                    {report.failureCode && <span className="muted"> · {t(`reportFailure.${report.failureCode}`)}</span>}
                  </td>
                  <td className="actions">
                    {report.state === 'ready' && (
                      <a className="button button-secondary" href={`${org(id)}/reports/${report.id}/download`} download>
                        {t('reports.download')}
                      </a>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  );
}
