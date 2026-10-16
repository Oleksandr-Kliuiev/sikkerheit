import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useOutletContext } from 'react-router';
import { idempotencyKey, patch, post } from '../../api/client';
import { org, useDevices, useEnrollmentKeys } from '../../api/hooks';
import type { Device, DeviceDecision, EnrollmentKey, EnrollmentKeySummary, Organization, ScanRequest } from '../../api/types';
import { Badge, Button, Dialog, Empty, ErrorMessage, Facts, Field, Loading, Notice, Section } from '../../components/ui';
import { useI18n } from '../../i18n/i18n';
import { useAuth } from '../../lib/auth';
import { decisionsFor, deviceTone } from '../../lib/devices';
import { formatDateTime } from '../../lib/format';
import { useOrganizationId } from './OrganizationLayout';

/** Windows devices and enrollment keys of the customer (FR-09, FR-10; 04 «Регистрация и аутентификация агента»). */
export function DevicesTab() {
  const { isAdmin } = useAuth();
  const organization = useOutletContext<Organization>();
  return (
    <div className="stack">
      <DevicesCard organization={organization} />
      {isAdmin && <KeysCard organization={organization} />}
    </div>
  );
}

function DevicesCard({ organization }: { organization: Organization }) {
  const { t, locale } = useI18n();
  const id = useOrganizationId();
  const [status, setStatus] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const devices = useDevices(id, { status });
  const items = devices.data?.pages.flatMap((page) => page.items) ?? [];
  const current = items.find((device) => device.id === selected) ?? null;
  return (
    <Section title={t('devices.title')} id="devices-title">
      <p className="muted">{t('devices.lead')}</p>
      <div className="form-row align-end">
        <Field label={t('devices.filterStatus')}>
          {(fieldId) => (
            <select id={fieldId} value={status} onChange={(event) => setStatus(event.target.value)}>
              <option value="">{t('common.all')}</option>
              <option value="active">{t('deviceStatus.active')}</option>
              <option value="revoked">{t('deviceStatus.revoked')}</option>
            </select>
          )}
        </Field>
      </div>
      {devices.isPending && <Loading />}
      <ErrorMessage error={devices.error} onRetry={() => void devices.refetch()} />
      {devices.data && items.length === 0 && <Empty>{t('devices.empty')}</Empty>}
      {items.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">{t('devices.name')}</th>
                <th scope="col">{t('devices.status')}</th>
                <th scope="col">{t('devices.identity')}</th>
                <th scope="col">{t('devices.agent')}</th>
                <th scope="col">{t('devices.lastSeen')}</th>
                <th scope="col">{t('devices.lastFullScan')}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((device) => (
                <tr key={device.id} className="clickable" onClick={() => setSelected(device.id)}>
                  <th scope="row" className="wrap">
                    <button type="button" className="link-button" onClick={() => setSelected(device.id)}>
                      {device.displayName}
                    </button>
                  </th>
                  <td>
                    <Badge tone={deviceTone(device)}>{t(`deviceStatus.${device.status}`)}</Badge>
                    {device.dormant && device.status === 'active' && (
                      <>
                        {' '}
                        <Badge tone="warn">{t('devices.dormant')}</Badge>
                      </>
                    )}
                    {device.clockStatus === 'inconsistent' && (
                      <>
                        {' '}
                        <Badge tone="warn">{t('clock.inconsistent')}</Badge>
                      </>
                    )}
                  </td>
                  <td>
                    <Badge tone={device.identityState === 'ok' ? 'neutral' : 'bad'}>{t(`identity.${device.identityState}`)}</Badge>
                  </td>
                  <td>{device.agentVersion ?? '—'}</td>
                  <td>{formatDateTime(device.lastSeenAt, locale)}</td>
                  <td>{formatDateTime(device.lastFullScanAt, locale)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {devices.hasNextPage && (
        <Button busy={devices.isFetchingNextPage} onClick={() => void devices.fetchNextPage()}>
          {t('common.loadMore')}
        </Button>
      )}
      {current && <DeviceDialog device={current} organization={organization} onClose={() => setSelected(null)} />}
    </Section>
  );
}

function DeviceDialog({ device, organization, onClose }: { device: Device; organization: Organization; onClose: () => void }) {
  const { t, locale } = useI18n();
  const { isAdmin, canWork } = useAuth();
  const id = useOrganizationId();
  const client = useQueryClient();
  const refresh = () => client.invalidateQueries({ queryKey: ['devices', id] });
  const [name, setName] = useState(device.displayName);
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [requested, setRequested] = useState<ScanRequest | null>(null);
  const rename = useMutation({
    mutationFn: () => patch<Device>(`${org(id)}/devices/${device.id}`, { displayName: name.trim() }),
    onSuccess: refresh,
  });
  const revoke = useMutation({
    mutationFn: () => post<void>(`${org(id)}/devices/${device.id}/revoke`, {}),
    onSuccess: async () => {
      setConfirmRevoke(false);
      await refresh();
    },
  });
  const scan = useMutation({
    mutationFn: () => post<ScanRequest>(`${org(id)}/devices/${device.id}/scan-requests`, { idempotencyKey: idempotencyKey(), reason: 'verify_remediation' }),
    onSuccess: (request) => setRequested(request),
  });
  const resolve = useMutation({
    mutationFn: (decision: DeviceDecision) => post<Device>(`${org(id)}/devices/${device.id}/identity-resolutions`, { decision }),
    onSuccess: refresh,
  });
  const active = device.status === 'active';
  const decisions = decisionsFor(device.identityConflict);
  return (
    <Dialog open onClose={onClose} wide title={device.displayName}
      footer={<Button onClick={onClose}>{t('common.close')}</Button>}>
      <Facts
        items={[
          [t('devices.status'), t(`deviceStatus.${device.status}`)],
          [t('devices.protection'), t(`keyProtection.${device.keyProtection}`)],
          [t('devices.clock'), t(`clock.${device.clockStatus}`)],
          [t('devices.agent'), device.agentVersion ?? '—'],
          [t('devices.enrolledAt'), formatDateTime(device.enrolledAt, locale)],
          [t('devices.lastSeen'), formatDateTime(device.lastSeenAt, locale)],
          [t('devices.lastFullScan'), formatDateTime(device.lastFullScanAt, locale)],
        ]}
      />
      {device.identityConflict && (
        <Notice tone="bad">
          <strong>{t('devices.conflictTitle')}</strong> {t(`conflictKind.${device.identityConflict.kind}`)} ·{' '}
          {t('devices.conflictSince', { time: formatDateTime(device.identityConflict.at, locale) })}
          {device.identityConflict.reportedDisplayName && (
            <> · {t('devices.reportedName', { name: device.identityConflict.reportedDisplayName })}</>
          )}
          <p>{t('devices.conflictHelp')}</p>
          {isAdmin && (
            <div className="actions-row">
              {decisions.map((decision) => (
                <Button key={decision} busy={resolve.isPending} onClick={() => resolve.mutate(decision)}>
                  {t(`devices.decision.${decision}`)}
                </Button>
              ))}
            </div>
          )}
          <ErrorMessage error={resolve.error} />
        </Notice>
      )}
      {canWork && active && organization.status === 'active' && (
        <div className="stack">
          <p className="muted">{t('devices.scanLead')}</p>
          <div className="actions-row">
            <Button busy={scan.isPending} onClick={() => scan.mutate()}>
              {t('devices.requestScan')}
            </Button>
          </div>
          <ErrorMessage error={scan.error} />
          {requested && <Notice tone="good">{t('devices.scanRequested', { time: formatDateTime(requested.expiresAt, locale) })}</Notice>}
        </div>
      )}
      {isAdmin && organization.status === 'active' && (
        <div className="form-row align-end">
          <Field label={t('devices.newName')}>
            {(fieldId) => <input id={fieldId} value={name} maxLength={120} onChange={(event) => setName(event.target.value)} />}
          </Field>
          <Button busy={rename.isPending} disabled={!name.trim() || name.trim() === device.displayName} onClick={() => rename.mutate()}>
            {t('devices.rename')}
          </Button>
        </div>
      )}
      <ErrorMessage error={rename.error} />
      {isAdmin && active && (
        <div className="stack">
          {!confirmRevoke && (
            <Button variant="danger" onClick={() => setConfirmRevoke(true)}>
              {t('devices.revoke')}
            </Button>
          )}
          {confirmRevoke && (
            <Notice tone="warn">
              <p>{t('devices.revokeLead')}</p>
              <div className="actions-row">
                <Button variant="danger" busy={revoke.isPending} onClick={() => revoke.mutate()}>
                  {t('devices.revokeConfirm')}
                </Button>
                <Button onClick={() => setConfirmRevoke(false)}>{t('common.cancel')}</Button>
              </div>
            </Notice>
          )}
          <ErrorMessage error={revoke.error} />
        </div>
      )}
    </Dialog>
  );
}

function KeysCard({ organization }: { organization: Organization }) {
  const { t, locale } = useI18n();
  const id = useOrganizationId();
  const client = useQueryClient();
  const keys = useEnrollmentKeys(id, true);
  const [label, setLabel] = useState('');
  const [created, setCreated] = useState<EnrollmentKey | null>(null);
  const [confirm, setConfirm] = useState<EnrollmentKeySummary | null>(null);
  const refresh = () => client.invalidateQueries({ queryKey: ['enrollment-keys', id] });
  const create = useMutation({
    mutationFn: () => post<EnrollmentKey>(`${org(id)}/enrollment-keys`, { label: label.trim() }),
    onSuccess: async (key) => {
      setCreated(key);
      setLabel('');
      await refresh();
    },
  });
  const revoke = useMutation({
    mutationFn: (key: EnrollmentKeySummary) => post<void>(`${org(id)}/enrollment-keys/${key.id}/revoke`, {}),
    onSuccess: async () => {
      setConfirm(null);
      await refresh();
      await client.invalidateQueries({ queryKey: ['devices', id] });
    },
  });
  const items = keys.data ?? [];
  const activeCount = items.filter((key) => !key.revokedAt).length;
  return (
    <Section title={t('keys.title')} id="keys-title">
      <p className="muted">{t('keys.lead')}</p>
      {organization.status === 'active' && (
        <div className="form-row align-end">
          <Field label={t('keys.label')}>
            {(fieldId) => <input id={fieldId} value={label} maxLength={120} onChange={(event) => setLabel(event.target.value)} />}
          </Field>
          <Button variant="primary" busy={create.isPending} disabled={!label.trim() || activeCount >= 2} onClick={() => create.mutate()}>
            {t('keys.create')}
          </Button>
        </div>
      )}
      {activeCount >= 2 && <p className="help">{t('keys.limit')}</p>}
      <ErrorMessage error={create.error} />
      {keys.isPending && <Loading />}
      <ErrorMessage error={keys.error} onRetry={() => void keys.refetch()} />
      {keys.data && items.length === 0 && <Empty>{t('keys.empty')}</Empty>}
      {items.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">{t('keys.label')}</th>
                <th scope="col">{t('keys.prefix')}</th>
                <th scope="col">{t('keys.createdAt')}</th>
                <th scope="col">{t('keys.lastUsed')}</th>
                <th scope="col">{t('keys.devices')}</th>
                <th scope="col">{t('devices.status')}</th>
                <th scope="col">
                  <span className="visually-hidden">{t('common.actions')}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((key) => (
                <tr key={key.id}>
                  <th scope="row" className="wrap">
                    {key.label}
                  </th>
                  <td><span className="id">{key.keyPrefix}…</span></td>
                  <td>{formatDateTime(key.createdAt, locale)}</td>
                  <td>{formatDateTime(key.lastUsedAt, locale)}</td>
                  <td className="num">{key.enrolledDevices}</td>
                  <td>
                    <Badge tone={key.revokedAt ? 'neutral' : 'good'}>{t(key.revokedAt ? 'keys.revoked' : 'keys.active')}</Badge>
                  </td>
                  <td className="actions">
                    {!key.revokedAt && (
                      <Button variant="danger" onClick={() => setConfirm(key)}>
                        {t('keys.revoke')}
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Dialog open={created !== null} title={t('keys.secretTitle')} onClose={() => setCreated(null)}
        footer={<Button variant="primary" onClick={() => setCreated(null)}>{t('common.close')}</Button>}>
        {created && (
          <>
            <Notice tone="warn">{t('keys.secretLead')}</Notice>
            <p>
              <code className="secret" data-testid="enrollment-secret">
                {created.enrollmentKey}
              </code>
            </p>
            <Button onClick={() => void navigator.clipboard?.writeText(created.enrollmentKey)}>{t('common.copy')}</Button>
          </>
        )}
      </Dialog>
      <Dialog open={confirm !== null} title={t('keys.revokeTitle')} onClose={() => setConfirm(null)}
        footer={
          <>
            <Button onClick={() => setConfirm(null)}>{t('common.cancel')}</Button>
            <Button variant="danger" busy={revoke.isPending} onClick={() => confirm && revoke.mutate(confirm)}>
              {t('keys.revokeConfirm')}
            </Button>
          </>
        }>
        <p>{t('keys.revokeLead', { label: confirm?.label ?? '' })}</p>
        <ErrorMessage error={revoke.error} />
      </Dialog>
    </Section>
  );
}
