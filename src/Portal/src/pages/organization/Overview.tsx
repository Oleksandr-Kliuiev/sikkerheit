import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { idempotencyKey, post } from '../../api/client';
import { org, useConnection, useRuns } from '../../api/hooks';
import type { CollectionRun, ConsentStart, TenantConnection } from '../../api/types';
import { Badge, Button, Dialog, Empty, ErrorMessage, Facts, Field, Loading, Notice, Section } from '../../components/ui';
import { useI18n } from '../../i18n/i18n';
import { useAuth } from '../../lib/auth';
import { formatDateTime } from '../../lib/format';
import { connectionTone } from '../Organizations';
import { useOrganizationId } from './OrganizationLayout';

export function OverviewTab() {
  return (
    <div className="grid-2">
      <ConnectionCard />
      <RunsCard />
    </div>
  );
}

function ConnectionCard() {
  const { t, locale } = useI18n();
  const { isAdmin, canWork } = useAuth();
  const id = useOrganizationId();
  const client = useQueryClient();
  const connection = useConnection(id);
  const [consent, setConsent] = useState<ConsentStart | null>(null);
  const [startOpen, setStartOpen] = useState(false);
  const [confirmDisconnect, setConfirmDisconnect] = useState(false);
  const [queued, setQueued] = useState(false);
  const refresh = async () => {
    await client.invalidateQueries({ queryKey: ['connection', id] });
    await client.invalidateQueries({ queryKey: ['runs', id] });
    await client.invalidateQueries({ queryKey: ['organizations'] });
  };
  const verify = useMutation({ mutationFn: () => post<TenantConnection>(`${org(id)}/m365-connection/verify`, {}), onSuccess: refresh });
  const disconnect = useMutation({
    mutationFn: () => post<TenantConnection>(`${org(id)}/m365-connection/disconnect`, {}),
    onSuccess: async () => {
      setConfirmDisconnect(false);
      await refresh();
    },
  });
  const collect = useMutation({
    mutationFn: () => post<CollectionRun>(`${org(id)}/collection-runs`, { idempotencyKey: idempotencyKey() }),
    onSuccess: async () => {
      setQueued(true);
      await refresh();
    },
  });
  const data = connection.data;
  return (
    <Section title={t('connection.title')} id="connection-title"
      actions={data && (
        <Badge tone={connectionTone(data.status)}>{t(`connection.status.${data.status}`)}</Badge>
      )}>
      {connection.isPending && <Loading />}
      <ErrorMessage error={connection.error ?? verify.error ?? disconnect.error ?? collect.error} />
      {data && (
        <>
          {data.status === 'not_connected' && <p className="muted">{t('connection.notConnectedLead')}</p>}
          {data.entraTenantId && (
            <Facts items={[
              [t('connection.tenant'), [data.tenantDisplayName, data.primaryDomain].filter(Boolean).join(' · ') || data.entraTenantId],
              ['Tenant ID', <code key="id">{data.entraTenantId}</code>],
              [t('connection.connectedAt'), formatDateTime(data.connectedAt, locale)],
              [t('connection.lastCollection'), data.lastCollectionState
                ? `${formatDateTime(data.lastCollectedAt, locale)} · ${t(`runState.${data.lastCollectionState}`)}`
                : t('common.never')],
              [t('connection.entraP1'), data.entraP1 === null ? t('common.unknown') : data.entraP1 ? t('common.yes') : t('common.no')],
            ]} />
          )}
          {data.entraP1 === false && <Notice>{t('connection.entraP1Help')}</Notice>}
          {data.status === 'consent_pending' && data.pendingTenantId && (
            <Notice>
              {t('connection.expectedTenant', { tenant: data.pendingTenantId })}{' '}
              {data.pendingExpiresAt && t('connection.consentExpires', { time: formatDateTime(data.pendingExpiresAt, locale) })}
            </Notice>
          )}
          {queued && <Notice tone="good">{t('connection.collectQueued')}</Notice>}
          {data.capabilities.length > 0 && (
            <details className="modules">
              <summary>{t('connection.modules')}</summary>
              <ul className="module-list">
                {data.capabilities.map((capability) => (
                  <li key={capability.module}>
                    <span>{t(`module.${capability.module}`)}</span>
                    <Badge tone={capability.status === 'available' ? 'good' : capability.status === 'skipped' ? 'neutral' : 'warn'}>
                      {t(`capability.${capability.status}`)}
                    </Badge>
                  </li>
                ))}
              </ul>
            </details>
          )}
          <div className="button-row">
            {isAdmin && data.status !== 'active' && (
              <Button variant="primary" onClick={() => setStartOpen(true)}>
                {t('connection.startConsent')}
              </Button>
            )}
            {isAdmin && data.status === 'consent_pending' && (
              <Button busy={verify.isPending} onClick={() => verify.mutate()}>
                {t('connection.verify')}
              </Button>
            )}
            {canWork && data.status === 'active' && (
              <Button variant="primary" busy={collect.isPending} onClick={() => collect.mutate()}>
                {t('connection.collectNow')}
              </Button>
            )}
            {isAdmin && (data.status === 'active' || data.status === 'consent_pending') && (
              <Button variant="danger" onClick={() => setConfirmDisconnect(true)}>
                {t('connection.disconnect')}
              </Button>
            )}
          </div>
        </>
      )}
      <ConsentDialog open={startOpen} consent={consent} onConsent={setConsent} onClose={() => {
        setStartOpen(false);
        setConsent(null);
        void refresh();
      }} />
      <Dialog open={confirmDisconnect} onClose={() => setConfirmDisconnect(false)} title={t('connection.disconnect')}
        footer={
          <>
            <Button onClick={() => setConfirmDisconnect(false)}>{t('common.cancel')}</Button>
            <Button variant="danger" busy={disconnect.isPending} onClick={() => disconnect.mutate()}>
              {t('connection.disconnect')}
            </Button>
          </>
        }>
        <p>{t('connection.disconnectConfirm')}</p>
      </Dialog>
    </Section>
  );
}

function ConsentDialog({ open, consent, onConsent, onClose }: {
  open: boolean;
  consent: ConsentStart | null;
  onConsent: (consent: ConsentStart) => void;
  onClose: () => void;
}) {
  const { t, locale } = useI18n();
  const id = useOrganizationId();
  const [tenantHint, setTenantHint] = useState('');
  const [allowCompanyTenant, setAllowCompanyTenant] = useState(false);
  const [copied, setCopied] = useState(false);
  const start = useMutation({
    mutationFn: () => post<ConsentStart>(`${org(id)}/m365-connection/consent`, { tenantHint: tenantHint.trim(), allowCompanyTenant }),
    onSuccess: onConsent,
  });
  return (
    <Dialog open={open} onClose={onClose} title={t('connection.startConsent')} wide
      footer={consent ? <Button variant="primary" onClick={onClose}>{t('common.close')}</Button> : (
        <>
          <Button onClick={onClose}>{t('common.cancel')}</Button>
          <Button variant="primary" busy={start.isPending} disabled={!tenantHint.trim()} onClick={() => start.mutate()}>
            {t('connection.startConsent')}
          </Button>
        </>
      )}>
      <ErrorMessage error={start.error} />
      {!consent ? (
        <>
          <Field label={t('connection.tenantHint')}>
            {(fieldId) => <input id={fieldId} value={tenantHint} maxLength={255} placeholder="kunde.no" onChange={(e) => setTenantHint(e.target.value)} />}
          </Field>
          <label className="check">
            <input type="checkbox" checked={allowCompanyTenant} onChange={(e) => setAllowCompanyTenant(e.target.checked)} />
            {t('connection.allowCompanyTenant')}
          </label>
        </>
      ) : (
        <>
          <p>{t('connection.consentInstructions')}</p>
          <div className="copy-row">
            <input readOnly value={consent.consentUrl} aria-label={t('connection.startConsent')} onFocus={(e) => e.target.select()} />
            <Button onClick={() => {
              void navigator.clipboard?.writeText(consent.consentUrl).then(() => setCopied(true));
            }}>
              {copied ? t('common.copied') : t('common.copy')}
            </Button>
          </div>
          <p className="muted">
            {t('connection.expectedTenant', { tenant: consent.expectedTenantId })} · {t('connection.consentExpires', { time: formatDateTime(consent.expiresAt, locale) })}
          </p>
        </>
      )}
    </Dialog>
  );
}

function RunsCard() {
  const { t, locale } = useI18n();
  const id = useOrganizationId();
  const runs = useRuns(id);
  return (
    <Section title={t('runs.title')} id="runs-title">
      {runs.isPending && <Loading />}
      <ErrorMessage error={runs.error} />
      {runs.data && runs.data.items.length === 0 && <Empty>{t('runs.empty')}</Empty>}
      {runs.data && runs.data.items.length > 0 && (
        <div className="table-wrap">
          <table className="table compact">
            <thead>
              <tr>
                <th scope="col">{t('runs.queuedAt')}</th>
                <th scope="col">{t('runs.trigger')}</th>
                <th scope="col">{t('findings.state')}</th>
                <th scope="col">{t('runs.completedAt')}</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.items.map((run) => (
                <tr key={run.id}>
                  <td>{formatDateTime(run.queuedAt, locale)}</td>
                  <td>{t(`trigger.${run.trigger}`)}</td>
                  <td>
                    <Badge tone={run.state === 'completed' ? 'good' : run.state === 'failed' ? 'bad' : run.state === 'partial' ? 'warn' : 'info'}>
                      {t(`runState.${run.state}`)}
                    </Badge>
                    {run.failureCode && <span className="muted"> · {t(`runFailure.${run.failureCode}`)}</span>}
                  </td>
                  <td>{formatDateTime(run.completedAt, locale)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  );
}
