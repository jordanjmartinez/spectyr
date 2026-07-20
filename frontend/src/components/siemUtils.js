// Shared SIEM view utilities. The Stage 1.5 client-side query machinery
// (field=value search, dropdown taxonomies, client time windows) retired
// with the Stage 4 workbench: querying is server-side LCQL only (contract
// P8). What remains here are pure display helpers over already-sanitized
// payloads.

// Severity as a thin colored left edge (table rows and cards alike).
export const SEV_EDGE = { critical: '#b26666', high: '#c28e46', medium: '#d4cc6e', low: '#e2e6ea' };
export const sevColor = (sev) => SEV_EDGE[String(sev || '').toLowerCase()] || '#e2e6ea';

// Source-family colors: the muted categorical set the Alerts dashboard used.
export const SOURCE_COLORS = {
  DNS: '#5dc8ec', Firewall: '#2a96b8', 'Windows Security': '#4d7099',
  Sysmon: '#3a5fb8', 'Azure AD': '#1d3370', Proxy: '#6b54b8',
  Defender: '#7ba7cc', Veeam: '#2a6b7a',
};
export const sourceColor = (source) => SOURCE_COLORS[source] || '#8b949e';

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
