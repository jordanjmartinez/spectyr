import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiFetch } from '../api';
import EndpointDetail from './EndpointDetail';
import useIncidentScope from './useIncidentScope';
import { PageIntro, ErrorState, SegmentedToggle, ToolbarSearch } from './ui';
import {
  DeviceGlyph, PlatformBadge, platformFor, DEVICE_LABELS,
} from './icons';

// Endpoints tab (Stage 1). The data is a fixed session snapshot: it is
// fetched when the tab opens, on reset, and on pivot. No polling, no
// refresh affordance, no bulk actions.

export const StatusBadge = ({ status }) => (
  status === 'online' ? (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />Online
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-red-50 text-red-700 border border-red-200">
      <span className="w-1.5 h-1.5 rounded-full bg-red-500" />Offline
    </span>
  )
);

export const IsolationBadge = ({ isolation }) => (
  isolation === 'isolated' ? (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-600 text-white">Isolated</span>
  ) : (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border border-[#d0d7de] text-muted">Not Isolated</span>
  )
);

export const OsChip = ({ os }) => (
  <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs border border-[#d0d7de] text-muted whitespace-nowrap">{os}</span>
);

// Visual pass V2b/V7: the Windows glyph moved into the one icon system
// (icons.jsx); rows render the shared device-class + platform-badge
// identity from the REAL serialized fields.

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
                     activeIncidentId = null, onOpenResponse,
                     activeIncident = null }) => {
  const [org, setOrg] = useState({});
  const [rows, setRows] = useState([]);
  const [selected, setSelected] = useState(null);
  const [search, setSearch] = useState('');
  // Owner list-page uniformity (2026-10-12): the shared toolbar pattern --
  // status tabs with counts plus the search bar; the passive count line
  // is retired. (All is the default home; the owner's named Online /
  // Offline tabs isolate each status.)
  const [statusView, setStatusView] = useState('all'); // 'all'|'online'|'offline'
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

  useEffect(() => { setSelected(null); setStatusView('all'); setSearch(''); }, [resetTrigger]);

  // Rows derive from the ONE scope state (A1-A.3): 'loading' and 'error'
  // render zero rows; all-activity rows never render while a case is
  // selected.
  const q = search.trim().toLowerCase();
  const scopeRows = scope.rowPolicy === 'all' ? rows
    : scope.rowPolicy === 'scoped' ? rows.filter(r => scope.data.hosts.has(r.hostname))
      : [];
  // Toolbar derivations: tab counts over the scoped rows (pre-search), so
  // the tabs and the rows can never disagree with the scope context.
  const statusCounts = {
    all: scopeRows.length,
    online: scopeRows.filter(r => r.status === 'online').length,
    offline: scopeRows.filter(r => r.status !== 'online').length,
  };
  const filtered = scopeRows.filter(r =>
    (statusView === 'all' || (statusView === 'online' ? r.status === 'online' : r.status !== 'online'))
    && (!q || r.hostname.toLowerCase().includes(q) || r.ip.includes(q)
      || r.external_ip.includes(q) || r.os.toLowerCase().includes(q))
  );

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
      {/* VA1: functional subtitle + the ONE incident pill; the retired
          All-activity bar and the identity card are gone. */}
      <PageIntro
        incident={activeIncident}
        right={(
          <>
            <SegmentedToggle
              ariaLabel="Endpoint view"
              value={statusView}
              onChange={setStatusView}
              options={[
                ['all', `All ${statusCounts.all}`],
                ['online', `Online ${statusCounts.online}`],
                ['offline', `Offline ${statusCounts.offline}`],
              ]}
            />
            <ToolbarSearch value={search} onChange={setSearch} placeholder="Search endpoints..." />
          </>
        )}
      />
      {activeIncidentId && scope.status === 'error' && (
        <div className="mb-3 rounded-lg border border-[#e2e6ea] bg-[#faf6f0]">
          <ErrorState onRetry={scope.refetch}>
            Incident scope could not be loaded.
            {scope.data && (
              <span className="text-muted"> Displayed rows are from the last successful scope read.</span>
            )}
          </ErrorState>
        </div>
      )}

      {/* Owner list-page uniformity (2026-10-12): the passive count line
          is retired -- the toolbar tabs carry the same counts. */}
      <div className="bg-white border border-[#e2e6ea] rounded-xl overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="data-thead">
            <tr>
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
              <tr><td colSpan={COLUMNS.length} className="px-4 py-4 text-left text-muted">
                {scope.rowPolicy === 'loading' ? 'Loading incident scope'
                  : scope.rowPolicy === 'error' ? 'Incident scope could not be loaded.'
                    : rows.length === 0 ? 'No endpoints yet. Hosts appear as scenarios reach the queue.' : 'No endpoints in this view.'}
              </td></tr>
            )}
            {sorted.map(r => {
              const ident = platformFor(r);
              return (
              <tr key={r.hostname} className="border-b border-[#eef1f4] last:border-b-0 hover:bg-[#f6f8fa]">
                <td className="px-3 sm:px-4 py-3 whitespace-nowrap">
                  <button
                    type="button"
                    onClick={() => setSelected(r.hostname)}
                    className="inline-flex items-center gap-2 log-mono text-[#16436b] hover:underline"
                  >
                    <DeviceGlyph deviceKind={ident.deviceKind} size={16} className="text-muted" />
                    {r.hostname}
                  </button>
                </td>
                <td className="px-3 sm:px-4 py-3">
                  <span className="inline-flex items-center gap-1.5 text-muted">
                    <PlatformBadge platformKey={ident.platformKey} />
                    <span className="text-xs">{DEVICE_LABELS[ident.deviceKind]}</span>
                  </span>
                </td>
                <td className="px-3 sm:px-4 py-3"><OsChip os={r.os} /></td>
                <td className="px-3 sm:px-4 py-3 log-mono whitespace-nowrap">{r.ip}</td>
                <td className="px-3 sm:px-4 py-3 log-mono whitespace-nowrap">{r.external_ip}</td>
                <td className="px-3 sm:px-4 py-3 text-muted">-</td>
                <td className="px-3 sm:px-4 py-3 whitespace-nowrap text-muted">{shortDate(r.first_seen)}</td>
                <td className="px-3 sm:px-4 py-3 whitespace-nowrap text-muted">{r.status === 'online' ? 'just now' : shortDate(r.last_seen)}</td>
                <td className="px-3 sm:px-4 py-3"><StatusBadge status={r.status} /></td>
                <td className="px-3 sm:px-4 py-3"><IsolationBadge isolation={r.isolation} /></td>
              </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Endpoints;
