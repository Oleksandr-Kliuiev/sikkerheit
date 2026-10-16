import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useOutletContext } from 'react-router';
import { idempotencyKey, patch, post } from '../../api/client';
import { org, useAudit, useExport, useStaff } from '../../api/hooks';
import type { Organization, OrganizationExport } from '../../api/types';
import { Badge, Button, ErrorMessage, Field, Loading, Notice, Section } from '../../components/ui';
import { useI18n, type Language } from '../../i18n/i18n';
import { useAuth } from '../../lib/auth';
import { formatDateTime } from '../../lib/format';
import { useOrganizationId } from './OrganizationLayout';

export function SettingsTab() {
  const { isAdmin } = useAuth();
  const { t } = useI18n();
  if (!isAdmin) {
    return <Notice>{t('problem.forbidden')}</Notice>;
  }
  return (
    <div className="stack">
      <div className="grid-2">
        <DetailsCard />
        <LifecycleCard />
      </div>
      <ExportCard />
      <AuditCard />
    </div>
  );
}

function useOrganizationRefresh() {
  const client = useQueryClient();
  const id = useOrganizationId();
  return async () => {
    await client.invalidateQueries({ queryKey: ['organization', id] });
    await client.invalidateQueries({ queryKey: ['organizations'] });
    await client.invalidateQueries({ queryKey: ['audit', id] });
  };
}

function DetailsCard() {
  const { t } = useI18n();
  const organization = useOutletContext<Organization>();
  const refresh = useOrganizationRefresh();
  const [name, setName] = useState(organization.name);
  const [timezone, setTimezone] = useState(organization.timezone);
  const [reportLanguage, setReportLanguage] = useState<Language>(organization.reportLanguage);
  const [saved, setSaved] = useState(false);
  const save = useMutation({
    mutationFn: () => patch<Organization>(org(organization.id), { name: name.trim(), timezone, reportLanguage }),
    onSuccess: async () => {
      setSaved(true);
      await refresh();
    },
  });
  return (
    <Section title={t('settings.details')} id="details-title">
      <ErrorMessage error={save.error} />
      {saved && <Notice tone="good">{t('settings.saved')}</Notice>}
      <fieldset disabled={organization.status !== 'active'}>
        <Field label={t('orgs.name')}>
          {(id) => <input id={id} value={name} maxLength={120} onChange={(event) => setName(event.target.value)} />}
        </Field>
        <Field label={t('orgs.timezone')}>
          {(id) => <input id={id} value={timezone} maxLength={80} onChange={(event) => setTimezone(event.target.value)} />}
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
        <Button variant="primary" busy={save.isPending} disabled={!name.trim()} onClick={() => save.mutate()}>
          {t('common.save')}
        </Button>
      </fieldset>
    </Section>
  );
}

const transitions: Record<Organization['status'], ('disable' | 'enable' | 'schedule_deletion' | 'cancel_deletion')[]> = {
  active: ['disable'],
  disabled: ['enable', 'schedule_deletion'],
  deletion_scheduled: ['cancel_deletion'],
};

function LifecycleCard() {
  const { t, locale } = useI18n();
  const organization = useOutletContext<Organization>();
  const refresh = useOrganizationRefresh();
  const [reason, setReason] = useState('');
  const [exportWaived, setExportWaived] = useState(false);
  const change = useMutation({
    mutationFn: (action: string) => post<Organization>(`${org(organization.id)}/lifecycle`, {
      action, reason: reason.trim(), idempotencyKey: idempotencyKey(),
      ...(action === 'schedule_deletion' ? { exportWaived } : {}),
    }),
    onSuccess: async () => {
      setReason('');
      setExportWaived(false);
      await refresh();
    },
  });
  return (
    <Section title={t('settings.lifecycle')} id="lifecycle-title"
      actions={<Badge tone={organization.status === 'active' ? 'good' : 'warn'}>{t(`orgStatus.${organization.status}`)}</Badge>}>
      <p className="muted">{t('settings.lifecycleLead')}</p>
      {organization.deletionDueAt && (
        <Notice tone="warn">{t('settings.deletionDue', { time: formatDateTime(organization.deletionDueAt, locale) })}</Notice>
      )}
      <ErrorMessage error={change.error} />
      <Field label={t('settings.reason')}>
        {(id) => <textarea id={id} rows={2} maxLength={1000} value={reason} onChange={(event) => setReason(event.target.value)} />}
      </Field>
      {organization.status === 'disabled' && (
        <label className="check">
          <input type="checkbox" checked={exportWaived} onChange={(event) => setExportWaived(event.target.checked)} />
          {t('settings.exportWaived')}
        </label>
      )}
      <div className="button-row">
        {transitions[organization.status].map((action) => (
          <Button key={action} variant={action === 'schedule_deletion' || action === 'disable' ? 'danger' : 'primary'}
            busy={change.isPending} disabled={!reason.trim()} onClick={() => change.mutate(action)}>
            {t(`settings.action.${action}`)}
          </Button>
        ))}
      </div>
    </Section>
  );
}

function ExportCard() {
  const { t, locale } = useI18n();
  const id = useOrganizationId();
  const [exportId, setExportId] = useState<string | null>(null);
  const status = useExport(id, exportId);
  const create = useMutation({
    mutationFn: () => post<OrganizationExport>(`${org(id)}/exports`, { idempotencyKey: idempotencyKey() }),
    onSuccess: (created) => setExportId(created.id),
  });
  const current = status.data;
  return (
    <Section title={t('settings.export')} id="export-title">
      <p className="muted">{t('settings.exportLead')}</p>
      <ErrorMessage error={create.error ?? status.error} />
      {current && (
        <Notice tone={current.state === 'ready' ? 'good' : current.state === 'queued' ? 'info' : 'bad'}>
          {t(`exportState.${current.state}`)}{' '}
          {current.state === 'ready' && current.expiresAt && t('settings.exportExpires', { time: formatDateTime(current.expiresAt, locale) })}
        </Notice>
      )}
      <div className="button-row">
        <Button variant="primary" busy={create.isPending || current?.state === 'queued'} onClick={() => create.mutate()}>
          {t('settings.createExport')}
        </Button>
        {current?.state === 'ready' && (
          <a className="button button-secondary" href={`${org(id)}/exports/${current.id}/download`} download>
            {t('settings.downloadExport')}
          </a>
        )}
      </div>
    </Section>
  );
}

function AuditCard() {
  const { t, locale } = useI18n();
  const id = useOrganizationId();
  const [open, setOpen] = useState(false);
  const audit = useAudit(id, open);
  const staff = useStaff();
  const names = new Map((staff.data ?? []).map((member) => [member.entraUserId, member.displayName ?? member.entraUserId]));
  const items = audit.data?.pages.flatMap((page) => page.items) ?? [];
  return (
    <Section title={t('settings.audit')} id="audit-title">
      <details onToggle={(event) => setOpen(event.currentTarget.open)}>
        <summary>{t('common.details')}</summary>
        {audit.isPending && open && <Loading />}
        <ErrorMessage error={audit.error} />
        {items.length > 0 && (
          <div className="table-wrap">
            <table className="table compact">
              <thead>
                <tr>
                  <th scope="col">{t('audit.time')}</th>
                  <th scope="col">{t('audit.actor')}</th>
                  <th scope="col">{t('audit.action')}</th>
                  <th scope="col">{t('audit.target')}</th>
                  <th scope="col">{t('audit.outcome')}</th>
                </tr>
              </thead>
              <tbody>
                {items.map((event) => (
                  <tr key={event.id}>
                    <td>{formatDateTime(event.occurredAt, locale)}</td>
                    <td>{event.actorType === 'system' ? t('audit.system') : names.get(event.actorId ?? '') ?? event.actorId}</td>
                    <td><code>{event.action}</code></td>
                    <td className="wrap"><code>{event.targetType}:{event.targetId}</code></td>
                    <td>{event.outcome}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {audit.hasNextPage && (
          <Button busy={audit.isFetchingNextPage} onClick={() => void audit.fetchNextPage()}>
            {t('common.loadMore')}
          </Button>
        )}
      </details>
    </Section>
  );
}
