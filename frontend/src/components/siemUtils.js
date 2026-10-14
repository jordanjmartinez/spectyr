// Shared SIEM view utilities. The Stage 1.5 client-side query machinery
// (field=value search, dropdown taxonomies, client time windows) retired
// with the Stage 4 workbench: querying is server-side LCQL only (contract
// P8). What remains here are pure display helpers over already-sanitized
// payloads.

// (The severity-edge and source-family color helpers retired with the
// playtest micro-fixes 2026-10-13: severity and source read as text on
// every SIEM surface now.)

// The raw-log JSON a SIEM would store. The server already whitelists the
// payload; this display list is a render convenience, not the disclosure
// boundary.
const RAW_LOG_FIELDS = [
  'timestamp', 'event_type', 'source_type', 'severity', 'hostname',
  'source_ip', 'destination_ip', 'user_account', 'message', 'key_value_pairs',
];
export const sanitizeEvent = (alert) => {
  const out = {};
  for (const k of RAW_LOG_FIELDS) {
    if (alert[k] !== undefined && alert[k] !== null && alert[k] !== '') out[k] = alert[k];
  }
  return out;
};

// Type-aware field-value rendering (contract Section 10.3/12): datetimes
// localized, byte counts humanized, everything else literal. Used by the
// field sidebar (top values) and the event inspector (every field).
const ISO_DATETIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;

export const formatDatetime = (iso) => {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return String(iso);
  return new Date(t).toLocaleString('en-GB', { hour12: false });
};

export const humanizeBytes = (n) => {
  const num = Number(n);
  if (!Number.isFinite(num)) return String(n);
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = num;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  const rounded = Number.isInteger(v) ? v : Math.round(v * 10) / 10;
  return `${rounded} ${units[i]}`;
};

export const renderFieldValue = (field, value) => {
  const str = String(value);
  if (field === 'timestamp' || ISO_DATETIME_RE.test(str)) return formatDatetime(value);
  if (/bytes/i.test(field) && !/_human$/i.test(field) && /^\d+$/.test(str)) {
    return humanizeBytes(value);
  }
  return str;
};
