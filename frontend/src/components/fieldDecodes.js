// Owner SIEM simplification pass (2026-10-13): plain-language decodes and
// facet-group vocabulary. Pure display data + pure functions: no React, no
// fetch, no access to anything but the values a caller passes in. Decoding
// never changes what is filtered or sent to the server -- the raw value is
// always the query value; the decoded text is a reading aid beside it.

// --- event-type decodes (the "Event" facet) ---------------------------------
// Covers the corpus vocabulary: Windows Security / Defender / Veeam numeric
// codes, Sysmon operational names, proxy / DNS / firewall verbs, and the
// Azure AD log names. An unmapped type renders raw.
export const EVENT_TYPE_LABELS = {
  // Windows Security
  4624: 'Successful Logon',
  4625: 'Failed Logon',
  4634: 'Logoff',
  4647: 'User-Initiated Logoff',
  4648: 'Logon With Explicit Credentials',
  4663: 'Object Access',
  4672: 'Admin Privileges Assigned',
  4688: 'Process Created',
  4740: 'Account Locked Out',
  4768: 'Kerberos Ticket Requested',
  1102: 'Audit Log Cleared',
  5140: 'Network Share Accessed',
  6416: 'External Device Connected',
  // Defender / Veeam
  5007: 'Defender Setting Changed',
  190: 'Backup Job Event',
  110: 'Backup Job Event',
  // Sysmon
  ProcessCreate: 'Process Started',
  ProcessTerminate: 'Process Ended',
  ProcessAccess: 'Process Memory Accessed',
  NetworkConnect: 'Network Connection',
  FileCreate: 'File Created',
  SetValue: 'Registry Value Set',
  ImageLoaded: 'Module Loaded',
  DNSQuery: 'DNS Lookup',
  WmiEventFilter: 'WMI Event Filter Registered',
  WmiEventConsumer: 'WMI Event Consumer Registered',
  WmiEventConsumerToFilter: 'WMI Filter-To-Consumer Binding',
  // DNS sensor
  QUERY: 'DNS Query',
  NXDOMAIN: 'DNS Name Not Found',
  // Proxy
  HTTP_GET: 'Web Request (GET)',
  HTTP_POST: 'Web Upload (POST)',
  HTTP_CONNECT: 'HTTPS Tunnel (CONNECT)',
  ALLOWED: 'Web Request Allowed',
  SESSION_END: 'Web Session Ended',
  SSL_INSPECT: 'SSL Inspection',
  SSL_HANDSHAKE_FAILED: 'SSL Handshake Failed',
  // Firewall
  ALLOW: 'Connection Allowed',
  DENY: 'Connection Blocked',
  // Azure AD
  SigninLogs: 'Cloud Sign-In',
  AADUserRiskEvents: 'Risky Sign-In Detected',
  FileSyncUploadedFull: 'Cloud File Upload',
};

// Windows logon types (4624/4625 logon_type).
export const LOGON_TYPE_LABELS = {
  2: 'Interactive (At Keyboard)',
  3: 'Network',
  4: 'Batch (Scheduled Task)',
  5: 'Service',
  7: 'Unlock',
  8: 'Network Cleartext',
  9: 'New Credentials (RunAs)',
  10: 'Remote Desktop (RDP)',
  11: 'Cached Interactive',
};

// NTSTATUS failure codes (4625 status / sub_status), keyed uppercase.
export const STATUS_CODE_LABELS = {
  '0X0': 'Success',
  '0X00000000': 'Success',
  '0XC000006A': 'Incorrect Password',
  '0XC000006D': 'Bad Username Or Password',
  '0XC000006E': 'Account Restriction',
  '0XC0000064': 'No Such User',
  '0XC0000070': 'Workstation Restriction',
  '0XC0000071': 'Password Expired',
  '0XC0000072': 'Account Disabled',
  '0XC0000193': 'Account Expired',
  '0XC0000224': 'Password Must Change',
  '0XC0000234': 'Account Locked Out',
};

// Azure AD sign-in ResultType codes.
export const RESULT_TYPE_LABELS = {
  0: 'Success',
  50053: 'Account Locked (Sign-In Blocked)',
  50076: 'MFA Required',
  50126: 'Invalid Username Or Password',
};

// The decoded reading of one field value, or null when no decode applies.
// The raw value is appended in parentheses so the technical identifier is
// never hidden: "Failed Logon (4625)", "Network (3)".
export function decodeFieldValue(field, value) {
  const v = String(value);
  if (field === 'event_type' && EVENT_TYPE_LABELS[v] !== undefined) {
    return `${EVENT_TYPE_LABELS[v]} (${v})`;
  }
  if (field === 'logon_type' && LOGON_TYPE_LABELS[v] !== undefined) {
    return `${LOGON_TYPE_LABELS[v]} (${v})`;
  }
  if ((field === 'status' || field === 'sub_status') &&
      STATUS_CODE_LABELS[v.toUpperCase()] !== undefined) {
    return `${STATUS_CODE_LABELS[v.toUpperCase()]} (${v})`;
  }
  if (field === 'ResultType' && RESULT_TYPE_LABELS[v] !== undefined) {
    return `${RESULT_TYPE_LABELS[v]} (${v})`;
  }
  return null;
}

// --- the facet-group vocabulary --------------------------------------------

// The six default groups, in rail order (owner spec, this pass).
export const DEFAULT_FACET_FIELDS = [
  'event_type', 'severity', 'user_account', 'hostname', 'source_ip',
  'source_type',
];

// Deleted as filter groups entirely (owner spec): identifiers and free text
// that made the old ~60-group rail unusable. event_seq is already excluded
// structurally (facetModel's FILTERABLE_TOP_FIELDS excludes it).
export const HIDDEN_FACET_FIELDS = [
  'id', 'timestamp', 'message', 'logon_guid', 'key_length', 'channel',
  'caller_process_id',
];

const GROUP_LABELS = {
  event_type: 'Event',
  severity: 'Severity',
  user_account: 'User Account',
  hostname: 'Computer',
  // Owner follow-up pass (2026-10-13): plain technical names, no gloss
  // (destination_ip renamed alongside for symmetry, flagged in the pass
  // report).
  source_ip: 'Source IP',
  destination_ip: 'Destination IP',
  source_type: 'Log Source',
  command_line: 'Command Line',
  image: 'Process',
  parent_image: 'Parent Process',
  target_filename: 'File Path',
  url: 'URL',
  query: 'DNS Query',
  workstation_name: 'Workstation',
  logon_type: 'Logon Type',
  sub_status: 'Failure Reason',
  status: 'Status Code',
  UserPrincipalName: 'User Principal Name',
  IPAddress: 'IP Address',
};

const ACRONYMS = new Set(['ip', 'dns', 'url', 'id', 'ssl', 'tls', 'http',
  'wmi', 'upn', 'guid', 'sid', 'pid', 'smb', 'mfa', 'utc']);

// Plain-language label for any field: the curated map first, then a
// Title-Case prettify of snake_case / PascalCase with acronyms uppercased.
export function labelForField(field) {
  if (GROUP_LABELS[field]) return GROUP_LABELS[field];
  const words = field.includes('_')
    ? field.split('_')
    : field.replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(' ');
  return words
    .filter((w) => w !== '')
    .map((w) => (ACRONYMS.has(w.toLowerCase())
      ? w.toUpperCase()
      : w.charAt(0).toUpperCase() + w.slice(1)))
    .join(' ');
}
