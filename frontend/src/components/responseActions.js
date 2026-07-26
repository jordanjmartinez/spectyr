// Final pass Part III.0.1: the ONE action system. One registry (verbs by
// target kind), one confirmation-spec source (copy moved VERBATIM from
// the retired execution sites on Detections and the Endpoint pages), one
// request path, one announcement (the T2/T3 toast), one log. The Response
// workspace is the only consumer that EXECUTES; every other surface only
// navigates here. Availability stays the server's job (preconditions,
// no-ops, and failures are its outcomes); the client reads only
// observable state for badges and disabled hints.
import { apiFetch } from '../api';
import { toastActionResult } from './uiToasts';
import { ACTION_LABELS } from './uiCopy';

export const PERSIST_LABEL = { wmi_subscription: 'WMI subscription', run_key: 'Run key' };

// The ONE request path. Resolves with the log entry; the toast is the one
// announcement (one fact, one announcement).
export const postResponseAction = (action, target) =>
  apiFetch('/api/actions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, target }),
  })
    .then(res => res.json())
    .then(entry => { toastActionResult(entry); return entry; });

// Confirmation specs per verb. `t` carries only observable identity:
// {entityId, hostname?, name?, pid?, account?, persistType?}.
export const confirmSpecs = {
  isolate_host: (t) => ({
    title: 'Isolate host',
    body: `Cut ${t.hostname} off from the network. Existing connections drop; the agent channel stays up.`,
    confirmLabel: 'Isolate', action: 'isolate_host', target: t.entityId,
  }),
  release_host: (t) => ({
    title: 'Release host',
    body: `Restore network connectivity for ${t.hostname}.`,
    confirmLabel: 'Release', action: 'release_host', target: t.entityId,
  }),
  kill_process: (t) => ({
    title: 'Kill process',
    body: `Terminate ${t.name} (PID ${t.pid}) on ${t.hostname}. The process record stays in the event log.`,
    confirmLabel: 'Kill', action: 'kill_process', target: t.entityId,
  }),
  remove_persistence: (t) => ({
    title: 'Remove persistence',
    body: `Remove the ${PERSIST_LABEL[t.persistType] || 'persistence'} "${t.name}" on ${t.hostname}. The originating events stay in the log.`,
    confirmLabel: 'Remove', action: 'remove_persistence', target: t.entityId,
  }),
  delete_file: (t) => ({
    title: 'Delete file',
    body: `Delete the on-disk payload backing "${t.name}" on ${t.hostname}. The event record is unchanged.`,
    confirmLabel: 'Delete', action: 'delete_file', target: t.entityId,
  }),
  disable_account: (t) => ({
    title: ACTION_LABELS.disable_account,
    body: `Disable the account ${t.account}. This is a response action; the detection record does not change.`,
    confirmLabel: 'Disable', action: 'disable_account', target: t.entityId,
  }),
  revoke_sessions: (t) => ({
    title: ACTION_LABELS.revoke_sessions,
    body: `Revoke all active sessions for ${t.account}. This is a response action; the detection record does not change.`,
    confirmLabel: 'Revoke', action: 'revoke_sessions', target: t.entityId,
  }),
  force_password_reset: (t) => ({
    title: ACTION_LABELS.force_password_reset,
    body: `Force a password reset for ${t.account}. This is a response action; the detection record does not change.`,
    confirmLabel: 'Reset', action: 'force_password_reset', target: t.entityId,
  }),
};
