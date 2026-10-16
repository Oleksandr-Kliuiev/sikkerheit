import type { Device } from '../api/types';

type Tone = 'neutral' | 'good' | 'warn' | 'bad' | 'info';

/** The state shown for a device, in the order of what matters to a technician (05 «Субъекты и идентичность устройства»). */
export function deviceTone(device: Pick<Device, 'status' | 'dormant' | 'identityState' | 'clockStatus'>): Tone {
  if (device.status === 'revoked') {
    return 'neutral';
  }
  if (device.identityState === 'identity_conflict') {
    return 'bad';
  }
  if (device.dormant || device.clockStatus === 'inconsistent') {
    return 'warn';
  }
  return 'good';
}

/** Decisions that fit the kind of the open identity conflict; «keep» always fits. */
export function decisionsFor(conflict: Device['identityConflict']): ('accept_new_fingerprint' | 'accept_new_key' | 'keep')[] {
  if (!conflict) {
    return [];
  }
  return [conflict.kind === 'fingerprint' ? 'accept_new_fingerprint' : 'accept_new_key', 'keep'];
}
