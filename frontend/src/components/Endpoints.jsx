import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiFetch } from '../api';
import EndpointDetail from './EndpointDetail';
import IncidentScopeBar from './IncidentScopeBar';
import useIncidentScope from './useIncidentScope';

// Endpoints tab (Stage 1). The data is a fixed session snapshot: it is
// fetched when the tab opens, on reset, and on pivot. No polling, no
// refresh affordance, no bulk actions.

export const StatusBadge = ({ status }) => (
  status === 'online' ? (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />ONLINE
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-red-50 text-red-700 border border-red-200">
      <span className="w-1.5 h-1.5 rounded-full bg-red-500" />OFFLINE
    </span>
  )
);

export const IsolationBadge = ({ isolation }) => (
  isolation === 'isolated' ? (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-600 text-white">Isolated</span>
  ) : (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border border-[#d0d7de] text-[#57606a]">Not Isolated</span>
  )
);

export const OsChip = ({ os }) => (
  <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs border border-[#d0d7de] text-[#57606a] whitespace-nowrap">{os}</span>
);

const WindowsIcon = () => (
  <svg role="img" aria-label="Windows" className="w-4 h-4 text-[#57606a]" viewBox="0 0 24 24" fill="currentColor">
    <path d="M3 5.1l7.4-1v7.3H3V5.1zm8.4-1.2L21 2.5v8.9h-9.6V3.9zM3 12.6h7.4v7.3L3 18.9v-6.3zm8.4 0H21v8.9l-9.6-1.4v-7.5z" />
  </svg>
);

const shortDate = (iso) => (iso ? iso.slice(0, 10) : '-');

const COLUMNS = [
  { key: 'hostname', label: 'Hostname' },
  { key: 'platform', label: 'Platform' },
  { key: 'os', label: 'OS' },
  { key: 'ip', label: 'Internal IP' },
  { key: 'external_ip', label: 'External IP' },
  { key: 'tags', label: 'Tags', sortable: false },
  { key: 'first_seen', label: 'First Seen' },
  { key: 'last_seen', label: 'Last Seen' },
  { key: 'status', label: 'Status' },
  { key: 'isolation', label: 'Isolation' },
];

const Endpoints = ({ isVisible, resetTrigger, pivotHost,
                     activeIncidentId = null, onOpenResponse }) => {
  const [org, setOrg] = useState({});
  const [rows, setRows] = useState([]);
  const [selected, setSelected] = useState(null);
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState({ key: 'hostname', dir: 'asc' });
  // Case-constant scope (Amendment 1 Delta A over the M1 foundation): ONE
  // scope state drives the pinned header, the honesty notices, and the row
  // filter. A selected case is ALWAYS case-scoped here; with no case the
  // list is the All activity state. Read-only.
  const scope = useIncidentScope(activeIncidentId, resetTrigger);
  const scopeRefetchRef = useRef(scope.refetch);
  scopeRefetchRef.current = scope.refetch;

  const fetchList = useCallback(() => {
    apiFetch('/api/endpoints')
      .then(res => res.json())
      .then(data => {
        setOrg(data.org || {});
        setRows(data.endpoints || []);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (isVisible) fetchList();
  }, [isVisible, resetTrigger, fetchList]);

  // M1 (contract 11.1): this surface deliberately has NO poll. The scope
  // refetches on every tab-visibility change (each time the view becomes
  // visible), plus the existing reset trigger (inside the hook) and the
  // pivot trigger below. No interval is introduced.
  useEffect(() => {
    if (isVisible) scopeRefetchRef.current();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isVisible]);

  // Pivot from an event view: open the named host directly.
  useEffect(() => {
    if (pivotHost?.value) {
      setSelected(pivotHost.value);
      fetchList();
      scopeRefetchRef.current();
    }
  }, [pivotHost, fetchList]);

  useEffect(() => { setSelected(null); }, [resetTrigger]);

  // Rows derive from the ONE scope state (A1-A.3): 'loading' and 'error'
  // render zero rows; all-activity rows never render while a case is
  // selected.
  const q = search.trim().toLowerCase();
  const scopeRows = scope.rowPolicy === 'all' ? rows
    : scope.rowPolicy === 'scoped' ? rows.filter(r => scope.data.hosts.has(r.hostname))
      : [];
  const filtered = scopeRows.filter(r =>
    (!q || r.hostname.toLowerCase().includes(q) || r.ip.includes(q)
      || r.external_ip.includes(q) || r.os.toLowerCase().includes(q))
  );
  const online = filtered.filter(r => r.status === 'online').length;

  // Stable sort: requested key first, hostname as the constant tiebreak.
  const sorted = [...filtered].sort((a, b) => {
    const va = String(a[sort.key] ?? '');
    const vb = String(b[sort.key] ?? '');
    const cmp = va.localeCompare(vb);
    const primary = sort.dir === 'asc' ? cmp : -cmp;
    return primary !== 0 ? primary : a.hostname.localeCompare(b.hostname);
  });

  const toggleSort = (key) => {
    setSort(s => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));
  };

  if (selected) {
    return (
      <EndpointDetail
        hostname={selected}
        org={org}
        onBack={() => setSelected(null)}
        onOpenResponse={onOpenResponse}
      />
    );
  }

  return (
    <div>
      {/* The case-constant header bar (pinned case line / All activity),
          rendered from the same state as the row filter so the signals
          cannot disagree. */}
      <IncidentScopeBar scope={scope} incidentId={activeIncidentId} />

      {/* Header card */}
      <div className="bg-white border border-[#e2e6ea] rounded-xl overflow-hidden mb-4">
        <div className="h-0.5" style={{ background: 'linear-gradient(to right, #16436b, #101218)' }} />
        <div className="p-4 sm:p-5 flex flex-wrap items-center gap-4">
          <div className="w-10 h-10 rounded-lg bg-[#101218] flex items-center justify-center shrink-0">
            <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" role="img" aria-label="Endpoints">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h2 className="text-xl sm:text-2xl font-semibold text-[#1a2332]">Endpoints</h2>
              <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-[#eef1f4] text-[#57606a]">{filtered.length}</span>
            </div>
            <p className="text-sm text-[#57606a] truncate">
              {org.name || 'ACME Corp'}: hosts in this scenario environment
            </p>
          </div>
          <div className="ml-auto w-full sm:w-64">
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search hostname, IP, OS"
              className="w-full px-3 py-2 text-sm rounded-md border border-[#d0d7de] bg-white text-[#1a2332] placeholder-[#8b949e] focus:outline-none focus:ring-2 focus:ring-[#16436b]/30"
            />
          </div>
        </div>
      </div>

      <p className="text-sm text-[#57606a] mb-2">{online} online &middot; {filtered.length - online} offline</p>

      <div className="bg-white border border-[#e2e6ea] rounded-xl overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="dark-thead">
            <tr className="text-xs uppercase tracking-wider">
              {COLUMNS.map(col => (
                <th key={col.key} className="px-3 sm:px-4 py-3 font-medium whitespace-nowrap">
                  {col.sortable === false ? col.label : (
                    <button type="button" onClick={() => toggleSort(col.key)} className="inline-flex items-center gap-1">
                      {col.label}
                      {sort.key === col.key && <span aria-hidden="true">{sort.dir === 'asc' ? '▴' : '▾'}</span>}
                    </button>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 && (
              <tr><td colSpan={COLUMNS.length} className="px-4 py-8 text-center text-[#8b949e]">
                {scope.rowPolicy === 'loading' ? 'Loading incident scope'
                  : scope.rowPolicy === 'error' ? 'Incident scope could not be loaded.'
                    : rows.length === 0 ? 'No endpoints yet. Hosts appear as scenarios reach the queue.' : 'No endpoints match the search.'}
              </td></tr>
            )}
            {sorted.map(r => (
              <tr key={r.hostname} className="border-b border-[#eef1f4] last:border-b-0 hover:bg-[#f6f8fa]">
                <td className="px-3 sm:px-4 py-3 whitespace-nowrap">
                  <button
                    type="button"
                    onClick={() => setSelected(r.hostname)}
                    className="font-mono text-[#16436b] hover:underline"
                  >
                    {r.hostname}
                  </button>
                </td>
                <td className="px-3 sm:px-4 py-3"><WindowsIcon /></td>
                <td className="px-3 sm:px-4 py-3"><OsChip os={r.os} /></td>
                <td className="px-3 sm:px-4 py-3 font-mono whitespace-nowrap">{r.ip}</td>
                <td className="px-3 sm:px-4 py-3 font-mono whitespace-nowrap">{r.external_ip}</td>
                <td className="px-3 sm:px-4 py-3 text-[#8b949e]">-</td>
                <td className="px-3 sm:px-4 py-3 whitespace-nowrap text-[#57606a]">{shortDate(r.first_seen)}</td>
                <td className="px-3 sm:px-4 py-3 whitespace-nowrap text-[#57606a]">{r.status === 'online' ? 'just now' : shortDate(r.last_seen)}</td>
                <td className="px-3 sm:px-4 py-3"><StatusBadge status={r.status} /></td>
                <td className="px-3 sm:px-4 py-3"><IsolationBadge isolation={r.isolation} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Endpoints;
