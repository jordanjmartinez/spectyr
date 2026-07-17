import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { apiFetch } from '../api';
import { StatusBadge, OsChip, IsolationBadge } from './Endpoints';
import ConfirmDialog from './ConfirmDialog';

// Endpoint detail (Stage 1): two-pane EDR-style view over the cached session
// snapshot. Fetched once per host; search and sort operate on the cached
// data only. Attack rows render identically to benign rows.
// Stage 3a: response actions. Isolate/Release live in the reserved control
// area on Overview; Kill Process on process rows. The server renders
// base+overlay, so a successful action shows up on refetch; failed attempts
// return an in-fiction reason that renders as a quiet notice line.

const shortDate = (iso) => (iso ? iso.slice(0, 10) : '-');
const shortDateTime = (iso) => (iso ? iso.slice(0, 16).replace('T', ' ') : '-');
const dash = (v) => (v === null || v === undefined || v === '' ? '-' : v);

const Card = ({ children, className = '' }) => (
  <div className={`bg-white border border-[#e2e6ea] rounded-xl overflow-hidden ${className}`}>
    <div className="h-0.5" style={{ background: 'linear-gradient(to right, #16436b, #101218)' }} />
    {children}
  </div>
);

const SectionLabel = ({ children }) => (
  <p className="text-[11px] uppercase tracking-wider text-[#6e7781] font-medium">{children}</p>
);

const SignerBadge = ({ signer, signed }) => (
  signed ? (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs bg-emerald-50 text-emerald-700 border border-emerald-200 whitespace-nowrap" title={signer || 'Signed'}>
      Signed
    </span>
  ) : (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs bg-red-50 text-red-700 border border-red-200">Unsigned</span>
  )
);

const TABS = [
  { key: 'overview', label: 'Overview', group: null },
  { key: 'processes', label: 'Processes', group: 'ENUMERATE' },
  { key: 'network', label: 'Network', group: 'ENUMERATE' },
  { key: 'services', label: 'Services', group: 'ENUMERATE' },
  { key: 'users', label: 'Users', group: 'ENUMERATE' },
  { key: 'autoruns', label: 'Autoruns', group: 'ENUMERATE' },
];

const Th = ({ children, onClick, active, dir }) => (
  <th className="px-3 py-2.5 font-medium whitespace-nowrap text-xs uppercase tracking-wider">
    {onClick ? (
      <button type="button" onClick={onClick} className="inline-flex items-center gap-1 uppercase tracking-wider">
        {children}{active && <span aria-hidden="true">{dir === 'asc' ? '▴' : '▾'}</span>}
      </button>
    ) : children}
  </th>
);

const EmptyRow = ({ span, text = 'None' }) => (
  <tr><td colSpan={span} className="px-4 py-6 text-center text-[#8b949e]">{text}</td></tr>
);

const EndpointDetail = ({ hostname, org, onBack }) => {
  const [snap, setSnap] = useState(null);
  const [notFound, setNotFound] = useState(false);
  const [tab, setTab] = useState('overview');
  const [procSearch, setProcSearch] = useState('');
  const [procSort, setProcSort] = useState({ key: 'pid', dir: 'asc' });
  const [confirm, setConfirm] = useState(null); // {title, body, confirmLabel, action, target}
  const [busy, setBusy] = useState(false);
  const [actionNotice, setActionNotice] = useState(null);

  const fetchSnap = useCallback(() => {
    apiFetch(`/api/endpoints/${encodeURIComponent(hostname)}`)
      .then(res => (res.ok ? res.json() : Promise.reject(res.status)))
      .then(setSnap)
      .catch(() => setNotFound(true));
  }, [hostname]);

  useEffect(() => {
    setSnap(null);
    setNotFound(false);
    setTab('overview');
    setConfirm(null);
    setActionNotice(null);
    fetchSnap();
  }, [hostname, fetchSnap]);

  const runAction = (action, target) => {
    setBusy(true);
    apiFetch('/api/actions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, target }),
    })
      .then(res => res.json())
      .then(entry => {
        setActionNotice(entry.outcome === 'success' ? null : (entry.reason || entry.error || null));
        setConfirm(null);
        setBusy(false);
        fetchSnap();
      })
      .catch(() => {
        setConfirm(null);
        setBusy(false);
      });
  };

  const processes = useMemo(() => {
    if (!snap) return [];
    const q = procSearch.trim().toLowerCase();
    const rows = snap.processes.filter(p =>
      !q || p.name.toLowerCase().includes(q) || p.path.toLowerCase().includes(q)
        || p.cmdline.toLowerCase().includes(q) || String(p.pid).includes(q)
        || p.user.toLowerCase().includes(q)
    );
    const dir = procSort.dir === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      const va = a[procSort.key], vb = b[procSort.key];
      const cmp = typeof va === 'number' && typeof vb === 'number'
        ? va - vb : String(va ?? '').localeCompare(String(vb ?? ''));
      return cmp !== 0 ? dir * cmp : a.pid - b.pid;
    });
  }, [snap, procSearch, procSort]);

  if (notFound) {
    return (
      <div>
        <button type="button" onClick={onBack} className="text-sm text-[#16436b] hover:underline mb-4">&larr; All Endpoints</button>
        <Card><div className="p-6 text-[#57606a]">
          <span className="font-mono text-[#1a2332]">{hostname}</span> is not a managed endpoint. Network devices appear in events but carry no agent snapshot.
        </div></Card>
      </div>
    );
  }

  if (!snap) {
    return (
      <div>
        <button type="button" onClick={onBack} className="text-sm text-[#16436b] hover:underline mb-4">&larr; All Endpoints</button>
        <p className="text-[#8b949e] text-sm">Loading endpoint...</p>
      </div>
    );
  }

  const sys = snap.system;
  const procSortBtn = (key) => () =>
    setProcSort(s => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));

  const tabTitle = TABS.find(t => t.key === tab)?.label || 'Overview';

  return (
    <div className="flex flex-col lg:flex-row gap-4 items-start">
      {/* Left mini-sidebar */}
      <aside className="w-full lg:w-60 shrink-0 lg:sticky lg:top-4">
        <Card>
          <div className="p-4">
            <button type="button" onClick={onBack} className="text-sm text-[#16436b] hover:underline">&larr; All Endpoints</button>
            <h3 className="mt-3 font-mono text-lg font-semibold text-[#1a2332] truncate" title={snap.hostname}>{snap.hostname}</h3>
            <div className="mt-2 flex flex-wrap gap-1.5">
              <StatusBadge status={snap.status} />
              {snap.isolation === 'isolated' && <IsolationBadge isolation="isolated" />}
            </div>
            <dl className="mt-4 space-y-2 text-xs">
              {[['OS', snap.os, false],
                ['Agent', sys.agent, true],
                ['Last seen', snap.status === 'online' ? 'just now' : shortDateTime(sys.last_heartbeat), false],
                ['IP', snap.ip, true],
                ['Org', org?.name || 'ACME Corp', false]].map(([k, v, mono]) => (
                <div key={k} className="flex justify-between gap-2 border-b border-[#eef1f4] pb-1.5 last:border-b-0">
                  <dt className="text-[#6e7781]">{k}</dt>
                  <dd className={`text-[#1a2332] text-right truncate ${mono ? 'font-mono' : ''}`} title={String(v)}>{v}</dd>
                </div>
              ))}
            </dl>
          </div>
          <nav className="border-t border-[#e2e6ea] p-2">
            {TABS.map((t, i) => (
              <React.Fragment key={t.key}>
                {t.group && TABS[i - 1]?.group !== t.group && (
                  <p className="px-3 pt-3 pb-1 text-[10px] uppercase tracking-wider text-[#8b949e]">{t.group}</p>
                )}
                <button
                  type="button"
                  onClick={() => setTab(t.key)}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                    tab === t.key ? 'bg-[#eef1f4] text-[#1a2332] font-medium' : 'text-[#57606a] hover:bg-[#f6f8fa]'
                  }`}
                >
                  {t.label}
                </button>
              </React.Fragment>
            ))}
          </nav>
        </Card>
      </aside>

      {/* Main pane */}
      <div className="flex-1 min-w-0 w-full">
        <h2 className="text-xl sm:text-2xl font-semibold text-[#1a2332]">{tabTitle}</h2>
        <p className="text-sm text-[#57606a] mb-4">
          <span className="font-mono">{snap.hostname}</span>{snap.desc ? `: ${snap.desc}` : ''}
        </p>

        {tab === 'overview' && (
          <div className="space-y-4">
            <Card>
              <div className="p-5">
                <div className="flex flex-wrap items-center gap-3">
                  <h3 className="font-mono text-2xl font-semibold text-[#1a2332]">{snap.hostname}</h3>
                  <StatusBadge status={snap.status} />
                  {snap.isolation === 'isolated' ? (
                    <IsolationBadge isolation="isolated" />
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-[#eef1f4] text-[#57606a]">Connected</span>
                  )}
                </div>
                <div className="mt-5 grid grid-cols-2 lg:grid-cols-4 gap-3">
                  {[['OS', snap.os, false],
                    ['Agent version', sys.agent_version, true],
                    ['Registered', shortDate(sys.registered), false],
                    ['Last heartbeat', snap.status === 'online' ? 'just now' : shortDateTime(sys.last_heartbeat), false]].map(([k, v, mono]) => (
                    <div key={k} className="rounded-lg border border-[#eef1f4] p-3">
                      <SectionLabel>{k}</SectionLabel>
                      <p className={`mt-1 text-sm text-[#1a2332] ${mono ? 'font-mono' : ''}`}>{v}</p>
                    </div>
                  ))}
                </div>
              </div>
            </Card>

            <Card>
              <div className="p-5">
                <SectionLabel>Network isolation</SectionLabel>
                <div className="mt-2 flex items-center justify-between gap-4">
                  <p className="text-sm text-[#57606a]">Isolation cuts the host off from the network while the agent channel stays up.</p>
                  {snap.isolation === 'isolated' ? (
                    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-red-600 text-white whitespace-nowrap">
                      <span className="w-1.5 h-1.5 rounded-full bg-white" />Isolated
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200 whitespace-nowrap">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />Connected
                    </span>
                  )}
                </div>
                <div className="mt-4 flex flex-wrap items-center gap-3">
                  {snap.isolation === 'isolated' ? (
                    <button
                      type="button"
                      onClick={() => setConfirm({
                        title: 'Release host',
                        body: `Restore network connectivity for ${snap.hostname}.`,
                        confirmLabel: 'Release',
                        action: 'release_host',
                        target: snap.entity_id,
                      })}
                      className="px-3 py-1.5 text-sm font-medium rounded-md border border-[#d0d7de] text-[#1a2332] hover:bg-[#eef1f4]"
                    >
                      Release Host
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setConfirm({
                        title: 'Isolate host',
                        body: `Cut ${snap.hostname} off from the network. Existing connections drop; the agent channel stays up.`,
                        confirmLabel: 'Isolate',
                        action: 'isolate_host',
                        target: snap.entity_id,
                      })}
                      className="px-3 py-1.5 text-sm font-medium rounded-md bg-[#101218] text-white hover:bg-[#1a2332]"
                    >
                      Isolate Host
                    </button>
                  )}
                  {actionNotice && <p className="text-xs text-[#57606a]">{actionNotice}</p>}
                </div>
              </div>
            </Card>

            <Card>
              <div className="p-5">
                <SectionLabel>System information</SectionLabel>
                <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-x-8">
                  {[['Platform', 'Windows', false],
                    ['Architecture', sys.architecture, true],
                    ['Internal IP', sys.internal_ip, true],
                    ['External IP', sys.external_ip, true],
                    ['MAC Address', sys.mac_address, true],
                    ['Sensor ID', sys.sensor_id, true],
                    ['Organization', org?.name || 'ACME Corp', false],
                    ['First Seen', shortDateTime(sys.first_seen), false]].map(([k, v, mono]) => (
                    <div key={k} className="flex justify-between gap-3 py-2 border-b border-[#eef1f4] text-sm">
                      <span className="text-[#6e7781]">{k}</span>
                      <span className={`text-[#1a2332] text-right break-all ${mono ? 'font-mono' : ''}`}>{dash(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            </Card>
          </div>
        )}

        {tab === 'processes' && (
          <Card>
            <div className="p-4 flex flex-wrap items-center gap-3">
              <input
                type="text"
                value={procSearch}
                onChange={e => setProcSearch(e.target.value)}
                placeholder="Search processes"
                className="w-full sm:w-72 px-3 py-2 text-sm rounded-md border border-[#d0d7de] bg-white text-[#1a2332] placeholder-[#8b949e] focus:outline-none focus:ring-2 focus:ring-[#16436b]/30"
              />
              <span className="text-sm text-[#57606a]">{processes.length} of {snap.processes.length}</span>
              {actionNotice && <span className="text-xs text-[#57606a]">{actionNotice}</span>}
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="dark-thead"><tr>
                  <Th onClick={procSortBtn('pid')} active={procSort.key === 'pid'} dir={procSort.dir}>PID</Th>
                  <Th onClick={procSortBtn('ppid')} active={procSort.key === 'ppid'} dir={procSort.dir}>PPID</Th>
                  <Th onClick={procSortBtn('path')} active={procSort.key === 'path'} dir={procSort.dir}>File Path</Th>
                  <Th>Command</Th>
                  <Th onClick={procSortBtn('user')} active={procSort.key === 'user'} dir={procSort.dir}>User</Th>
                  <Th onClick={procSortBtn('memory_mb')} active={procSort.key === 'memory_mb'} dir={procSort.dir}>Memory</Th>
                  <Th>Action</Th>
                </tr></thead>
                <tbody>
                  {processes.length === 0 && <EmptyRow span={7} />}
                  {processes.map(p => (
                    <tr key={`${p.pid}-${p.name}`} className="border-b border-[#eef1f4] last:border-b-0 align-top">
                      <td className="px-3 py-2 font-mono whitespace-nowrap">{p.pid}</td>
                      <td className="px-3 py-2 font-mono whitespace-nowrap">
                        {p.ppid}
                        {p.parent_terminated && <span className="ml-1.5 font-sans text-xs text-[#8b949e]">(terminated)</span>}
                      </td>
                      <td className="px-3 py-2 font-mono break-all min-w-[16rem]">{dash(p.path)}</td>
                      <td className="px-3 py-2 font-mono break-all min-w-[16rem] text-[#57606a]">{dash(p.cmdline)}</td>
                      <td className="px-3 py-2 font-mono whitespace-nowrap">{dash(p.user)}</td>
                      <td className="px-3 py-2 whitespace-nowrap text-[#57606a]">{p.memory_mb} MB</td>
                      <td className="px-3 py-2 whitespace-nowrap">
                        {p.entity_id && (
                          <button
                            type="button"
                            onClick={() => setConfirm({
                              title: 'Kill process',
                              body: `Terminate ${p.name} (PID ${p.pid}) on ${snap.hostname}. The process record stays in the event log.`,
                              confirmLabel: 'Kill',
                              action: 'kill_process',
                              target: p.entity_id,
                            })}
                            className="px-2.5 py-1 text-xs font-medium rounded-md border border-[#d0d7de] text-[#57606a] hover:bg-[#eef1f4]"
                          >
                            Kill
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}

        {tab === 'network' && (
          <div className="space-y-4">
            <Card>
              <div className="p-4"><SectionLabel>Connections</SectionLabel></div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="dark-thead"><tr>
                    <Th>Proto</Th><Th>Local Address</Th><Th>Remote Address</Th><Th>State</Th><Th>Process</Th>
                  </tr></thead>
                  <tbody>
                    {snap.network.connections.length === 0 && <EmptyRow span={5} />}
                    {snap.network.connections.map((c, i) => (
                      <tr key={i} className="border-b border-[#eef1f4] last:border-b-0">
                        <td className="px-3 py-2 font-mono uppercase whitespace-nowrap">{c.proto}</td>
                        <td className="px-3 py-2 font-mono whitespace-nowrap">{c.local_ip}{c.local_port ? `:${c.local_port}` : ''}</td>
                        <td className="px-3 py-2 font-mono whitespace-nowrap">{c.remote_ip === '-' ? '-' : `${c.remote_ip}${c.remote_port ? `:${c.remote_port}` : ''}`}</td>
                        <td className="px-3 py-2 whitespace-nowrap text-[#57606a]">{c.state}</td>
                        <td className="px-3 py-2 font-mono whitespace-nowrap">{c.process === '-' ? '-' : `${c.process}${c.pid ? ` (${c.pid})` : ''}`}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
            <Card>
              <div className="p-4"><SectionLabel>Recent DNS</SectionLabel></div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="dark-thead"><tr><Th>Domain</Th><Th>Resolved IPs</Th><Th>Process</Th></tr></thead>
                  <tbody>
                    {snap.network.dns.length === 0 && <EmptyRow span={3} />}
                    {snap.network.dns.map((d, i) => (
                      <tr key={i} className="border-b border-[#eef1f4] last:border-b-0">
                        <td className="px-3 py-2 font-mono break-all">{d.query}</td>
                        <td className="px-3 py-2 font-mono whitespace-nowrap">{dash(d.resolved)}</td>
                        <td className="px-3 py-2 font-mono whitespace-nowrap">{d.process === '-' ? '-' : `${d.process}${d.pid ? ` (${d.pid})` : ''}`}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          </div>
        )}

        {tab === 'services' && (
          <Card>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="dark-thead"><tr>
                  <Th>Name</Th><Th>Display Name</Th><Th>Status</Th><Th>Startup Type</Th><Th>Path</Th><Th>Log On As</Th>
                </tr></thead>
                <tbody>
                  {snap.services.length === 0 && <EmptyRow span={6} />}
                  {snap.services.map(svc => (
                    <tr key={svc.name} className="border-b border-[#eef1f4] last:border-b-0 align-top">
                      <td className="px-3 py-2 font-mono whitespace-nowrap">{svc.name}</td>
                      <td className="px-3 py-2">{svc.display_name}</td>
                      <td className="px-3 py-2">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs ${
                          svc.status === 'Running'
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                            : 'border border-[#d0d7de] text-[#57606a]'
                        }`}>{svc.status}</span>
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap text-[#57606a]">{svc.start_type}</td>
                      <td className="px-3 py-2 font-mono break-all min-w-[16rem]">{svc.path}</td>
                      <td className="px-3 py-2 font-mono whitespace-nowrap">{svc.account}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}

        {tab === 'users' && (
          <Card>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="dark-thead"><tr><Th>Username</Th><Th>Type</Th><Th>Groups</Th><Th>Last Logon</Th></tr></thead>
                <tbody>
                  {snap.users.length === 0 && <EmptyRow span={4} />}
                  {snap.users.map(u => (
                    <tr key={`${u.domain}-${u.username}`} className="border-b border-[#eef1f4] last:border-b-0">
                      <td className="px-3 py-2 font-mono whitespace-nowrap">
                        {u.domain && u.domain !== '-' ? `${u.domain}\\${u.username}` : u.username}
                        {!u.enabled && <span className="ml-2 font-sans text-xs text-[#8b949e]">(disabled)</span>}
                      </td>
                      <td className="px-3 py-2">
                        <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs border border-[#d0d7de] text-[#57606a]">{u.type}</span>
                      </td>
                      <td className="px-3 py-2 text-[#57606a]">{(u.groups && u.groups.length) ? u.groups.join(', ') : '-'}</td>
                      <td className="px-3 py-2 whitespace-nowrap text-[#57606a]">{shortDateTime(u.last_logon)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}

        {tab === 'autoruns' && (
          <Card>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="dark-thead"><tr><Th>Entry</Th><Th>Location</Th><Th>Image Path</Th><Th>Signer</Th></tr></thead>
                <tbody>
                  {snap.autoruns.length === 0 && <EmptyRow span={4} />}
                  {snap.autoruns.map((a, i) => (
                    <tr key={i} className="border-b border-[#eef1f4] last:border-b-0 align-top">
                      <td className="px-3 py-2 whitespace-nowrap">{a.name}</td>
                      <td className="px-3 py-2 font-mono break-all min-w-[14rem]">{a.location}</td>
                      <td className="px-3 py-2 font-mono break-all min-w-[14rem]">{a.command}</td>
                      <td className="px-3 py-2"><SignerBadge signer={a.signer} signed={!!a.signer} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}
      </div>

      <ConfirmDialog
        open={!!confirm}
        title={confirm?.title}
        body={confirm?.body}
        confirmLabel={confirm?.confirmLabel}
        busy={busy}
        onConfirm={() => confirm && runAction(confirm.action, confirm.target)}
        onCancel={() => setConfirm(null)}
      />
    </div>
  );
};

export default EndpointDetail;
