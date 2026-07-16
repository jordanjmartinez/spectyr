// Shared SIEM view utilities (Stage 1.5). Everything here operates on the
// cached session event pool: no regeneration, no wall-clock reads.

// Structured search: `field=value` tokens filter by column (AND-ed); bare
// words are all-field substring. e.g. `source_ip=10.0.1.24 event_type=4625`.
export const FIELD_ALIASES = {
  event_type: 'event_type', type: 'event_type', event: 'event_type',
  source_type: 'source_type', source: 'source_type', src_type: 'source_type',
  source_ip: 'source_ip', src_ip: 'source_ip', src: 'source_ip',
  destination_ip: 'destination_ip', dst_ip: 'destination_ip', dst: 'destination_ip',
  protocol: 'protocol', proto: 'protocol',
  message: 'message', msg: 'message',
  hostname: 'hostname', host: 'hostname',
  severity: 'severity', sev: 'severity',
};

export const parseEventQuery = (term) => {
  const fieldFilters = [];
  const free = [];
  for (const tok of term.trim().split(/\s+/)) {
    if (!tok) continue;
    const eq = tok.indexOf('=');
    if (eq > 0) {
      const field = FIELD_ALIASES[tok.slice(0, eq).toLowerCase()];
      const val = tok.slice(eq + 1).toLowerCase();
      if (field && val) { fieldFilters.push([field, val]); continue; }
    }
    free.push(tok.toLowerCase());
  }
  return { fieldFilters, free: free.join(' ') };
};

export const alertFieldValue = (alert, field) =>
  field === 'source_type' ? (alert.source_type || alert.detected_by || '') : (alert[field] ?? '');

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

// Platform taxonomy for the dropdown: display grouping of source families.
// The dropdown offers only the values present in the cached pool.
const PLATFORM_MAP = {
  Sysmon: 'Windows', 'Windows Security': 'Windows', Defender: 'Windows',
  'Azure AD': 'Cloud', Proxy: 'Network', Firewall: 'Network', DNS: 'Network',
  Veeam: 'Application',
};
export const platformOf = (alert) =>
  PLATFORM_MAP[alert.source_type || alert.detected_by] || 'Other';

// The raw-log JSON a SIEM would store. Simulation-internal fields (scenario
// wiring, answers, analyst state) must never reach the JSON view.
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

// Time presets anchored to the pool's own latest timestamp (scenario time),
// never wall time.
export const TIME_PRESETS = [
  { key: '15m', label: '15m', seconds: 15 * 60 },
  { key: '1h', label: '1h', seconds: 3600 },
  { key: '4h', label: '4h', seconds: 4 * 3600 },
  { key: '12h', label: '12h', seconds: 12 * 3600 },
  { key: '24h', label: '24h', seconds: 24 * 3600 },
  { key: 'all', label: 'All', seconds: null },
];

export const withinPreset = (alert, presetKey, anchorMs) => {
  const preset = TIME_PRESETS.find(p => p.key === presetKey);
  if (!preset || preset.seconds === null || anchorMs === null) return true;
  const ts = Date.parse(alert.timestamp || '');
  if (Number.isNaN(ts)) return false;
  return anchorMs - ts <= preset.seconds * 1000;
};

export const poolAnchorMs = (alerts) => {
  let max = null;
  for (const a of alerts) {
    const ts = Date.parse(a.timestamp || '');
    if (!Number.isNaN(ts) && (max === null || ts > max)) max = ts;
  }
  return max;
};
