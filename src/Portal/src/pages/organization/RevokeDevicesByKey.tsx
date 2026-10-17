import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { post } from '../../api/client';
import { org } from '../../api/hooks';
import type { Device } from '../../api/types';
import { Button, Dialog, ErrorMessage, Notice } from '../../components/ui';
import { useI18n } from '../../i18n/i18n';

/** RB-10: a confirmed snapshot; incomplete cursor lists cannot accidentally be presented as a complete revocation. */
export function RevokeDevicesByKey({ organizationId, keyId, devices, incomplete }: {
  organizationId: string; keyId: string; devices: Device[]; incomplete: boolean;
}) {
  const { t } = useI18n();
  const client = useQueryClient();
  const [snapshot, setSnapshot] = useState<Device[] | null>(null);
  const active = devices.filter((device) => device.status === 'active' && device.enrollmentKeyId === keyId);
  const revoke = useMutation({
    retry: false,
    mutationFn: async (items: Device[]) => {
      let completed = 0;
      const failures: string[] = [];
      let firstError: unknown = null;
      for (const item of items) {
        try {
          await post<void>(`${org(organizationId)}/devices/${item.id}/revoke`, {});
          completed++;
        } catch (error) {
          failures.push(item.id);
          firstError ??= error;
        }
      }
      return { completed, failures, firstError };
    },
    onSuccess: async () => {
      setSnapshot(null);
      await client.invalidateQueries({ queryKey: ['devices', organizationId] });
      await client.invalidateQueries({ queryKey: ['enrollment-keys', organizationId] });
    },
  });
  return <>
    <Button variant="danger" disabled={incomplete || active.length === 0} busy={revoke.isPending}
      onClick={() => { revoke.reset(); setSnapshot([...active]); }}>{t('devices.revokeByKey')}</Button>
    {incomplete && <p className="help">{t('devices.loadBeforeRevoke')}</p>}
    {revoke.data && <Notice tone={revoke.data.failures.length ? 'warn' : 'good'}>
      {t('devices.bulkResult', { completed: revoke.data.completed, failed: revoke.data.failures.length })}
      {revoke.data.failures.length > 0 && <p className="id">{revoke.data.failures.join(', ')}</p>}
    </Notice>}
    <ErrorMessage error={revoke.data?.firstError} />
    {snapshot && <Dialog open title={t('devices.revokeByKey')} onClose={() => { if (!revoke.isPending) setSnapshot(null); }}>
      <p>{t('devices.bulkLead', { count: snapshot.length })}</p>
      <ul>{snapshot.map((device) => <li key={device.id}>{device.displayName}</li>)}</ul>
      <div className="button-row">
        <Button variant="danger" busy={revoke.isPending} onClick={() => revoke.mutate(snapshot)}>{t('devices.revokeConfirm')}</Button>
        <Button disabled={revoke.isPending} onClick={() => setSnapshot(null)}>{t('common.cancel')}</Button>
      </div>
    </Dialog>}
  </>;
}
