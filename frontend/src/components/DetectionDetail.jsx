import React, { useState, useEffect } from 'react';
import { apiFetch } from '../api';
import { SeverityBadge, RuleTypeChip } from './Detections';

// Detection detail (Stage 2), the Section 8 card anatomy: lineage as
// first-class UI. Triggering Event card plus a stacked Parent Process card.
// SHA256 is fictional and shown with a copy button, never a VirusTotal link.

const basename = (p) => (p ? p.split('\\').pop().split('/').pop() : '');
const dash = (v) => (v === null || v === undefined || v === '' ? '-' : v);

const SectionLabel = ({ children }) => (
  <p className="text-[11px] uppercase tracking-wider text-[#6e7781] font-medium">{children}</p>
);

const Card = ({ children }) => (
  <div className="bg-white border border-[#e2e6ea] rounded-xl overflow-hidden">
    <div className="h-0.5" style={{ background: 'linear-gradient(to right, #16436b, #101218)' }} />
    {children}
  </div>
);

const SignatureBadge = ({ signer }) => (
  signer && signer !== '-' ? (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs bg-emerald-50 text-emerald-700 border border-emerald-200" title={signer}>Signed</span>
  ) : (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs bg-red-50 text-red-700 border border-red-200">Unsigned</span>
  )
);

const KvRow = ({ label, children, mono }) => (
  <div className="flex justify-between gap-3 py-2 border-b border-[#eef1f4] text-sm last:border-b-0">
    <span className="text-[#6e7781] shrink-0">{label}</span>
    <span className={`text-[#1a2332] text-right break-all ${mono ? 'font-mono' : ''}`}>{children}</span>
  </div>
);

// The triggering-event-plus-parent card stack. Renders reduced KV rows when a
// field is absent (e.g. non-process triggers like 1102 or DNS).
const ProcessCard = ({ title, name, cmdline, path, pid, ppid, signer, sha256, user }) => {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    if (!sha256) return;
    try { navigator.clipboard.writeText(sha256); setCopied(true); setTimeout(() => setCopied(false), 1200); } catch (e) { /* clipboard unavailable */ }
  };
  return (
    <Card>
      <div className="p-5">
        <SectionLabel>{title}</SectionLabel>
        <h3 className="mt-1 font-mono text-lg font-semibold text-[#1a2332] break-all">{name || '-'}</h3>
        {cmdline && (
          <pre className="mt-3 p-3 rounded-lg bg-[#f6f8fa] border border-[#eef1f4] text-xs font-mono text-[#1a2332] overflow-x-auto whitespace-pre-wrap break-all">{cmdline}</pre>
        )}
        <div className="mt-3">
          {path !== undefined && <KvRow label="File name" mono>{basename(path) || '-'}</KvRow>}
          {path !== undefined && <KvRow label="Full path" mono>{dash(path)}</KvRow>}
          {pid !== undefined && <KvRow label="PID" mono>{dash(pid)}</KvRow>}
          {ppid !== undefined && <KvRow label="Parent PID" mono>{dash(ppid)}</KvRow>}
          {user !== undefined && <KvRow label="User" mono>{dash(user)}</KvRow>}
          {signer !== undefined && <KvRow label="Signature"><SignatureBadge signer={signer} /></KvRow>}
          {sha256 !== undefined && (
            <KvRow label="SHA256">
              <span className="inline-flex items-center gap-2">
                <span className="font-mono text-xs break-all">{dash(sha256)}</span>
                {sha256 && (
                  <button type="button" onClick={copy} className="shrink-0 text-[#16436b] hover:underline text-xs" aria-label="Copy SHA256">
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                )}
              </span>
            </KvRow>
          )}
        </div>
      </div>
    </Card>
  );
};

const DetectionDetail = ({ detId, onBack, onAction, onHostPivot }) => {
  const [det, setDet] = useState(null);
  const [notFound, setNotFound] = useState(false);

  const load = () => {
    apiFetch(`/api/detections/${encodeURIComponent(detId)}`)
      .then(res => (res.ok ? res.json() : Promise.reject(res.status)))
      .then(setDet)
      .catch(() => setNotFound(true));
  };
  useEffect(() => { setDet(null); setNotFound(false); load(); /* eslint-disable-next-line */ }, [detId]);

  const doAction = (action) => {
    onAction?.(detId, action);
    // optimistic local update, then reload
    setDet(d => (d ? { ...d, player_action: action === 'promote' ? 'promoted' : action === 'dismiss' ? 'dismissed' : 'open' } : d));
    setTimeout(load, 300);
  };

  if (notFound) {
    return (
      <div>
        <button type="button" onClick={onBack} className="text-sm text-[#16436b] hover:underline mb-4">&larr; All detections</button>
        <Card><div className="p-6 text-[#57606a]">This detection is no longer available.</div></Card>
      </div>
    );
  }
  if (!det) {
    return (
      <div>
        <button type="button" onClick={onBack} className="text-sm text-[#16436b] hover:underline mb-4">&larr; All detections</button>
        <p className="text-[#8b949e] text-sm">Loading detection...</p>
      </div>
    );
  }

  const ev = (det.triggering_events || [])[0] || {};
  const kvp = ev.key_value_pairs || {};
  const isProcess = !!kvp.image;
  const hasParent = !!kvp.parent_image;

  return (
    <div className="space-y-4">
      <button type="button" onClick={onBack} className="text-sm text-[#16436b] hover:underline">&larr; All detections</button>

      {/* Detection header */}
      <Card>
        <div className="p-5">
          <div className="flex flex-wrap items-center gap-2">
            <SectionLabel>Detection</SectionLabel>
            <SeverityBadge severity={det.severity} />
            <RuleTypeChip type={det.rule_type} />
            {det.yara_rule_name && (
              <span className="font-mono text-xs text-[#57606a]">{det.yara_rule_name}</span>
            )}
          </div>
          <h2 className="mt-2 text-xl sm:text-2xl font-semibold text-[#1a2332]">{det.rule_name}</h2>
          <p className="mt-1 text-sm text-[#57606a] font-mono">
            {det.time ? det.time.slice(0, 19).replace('T', ' ') : '-'}
            {' '}&middot;{' '}
            {det.entity?.host ? (
              <button type="button" onClick={() => onHostPivot?.(det.entity.host)} className="text-[#16436b] hover:underline" title={`Open ${det.entity.host} in Endpoints`}>
                {det.entity.host}
              </button>
            ) : '-'}
            {' '}&middot;{' '}
            <span className="text-[#8b949e]">{det.id}</span>
          </p>
        </div>
      </Card>

      {/* Rule description, left-accent blockquote */}
      <div className="bg-white border border-[#e2e6ea] rounded-xl overflow-hidden">
        <div className="p-5 border-l-[3px]" style={{ borderLeftColor: '#16436b' }}>
          <SectionLabel>Rule</SectionLabel>
          <p className="mt-1.5 text-sm text-[#1a2332] leading-relaxed">{det.description}</p>
        </div>
      </div>

      {/* MITRE ATT&CK */}
      {det.mitre && (
        <Card>
          <div className="p-5">
            <SectionLabel>MITRE ATT&amp;CK</SectionLabel>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs border border-[#d0d7de] text-[#57606a]">{det.mitre.tactic}</span>
              <span className="font-mono text-xs text-[#57606a]">{det.mitre.id}</span>
            </div>
          </div>
        </Card>
      )}

      {/* Triggering event, then parent process: lineage as first-class UI */}
      <ProcessCard
        title="Triggering event"
        name={isProcess ? basename(kvp.image) : ev.event_type}
        cmdline={kvp.command_line}
        path={isProcess ? kvp.image : undefined}
        pid={isProcess ? kvp.process_id : undefined}
        ppid={isProcess ? kvp.parent_process_id : undefined}
        signer={isProcess ? kvp.company : undefined}
        sha256={det.sha256 !== null && det.sha256 !== undefined ? det.sha256 : undefined}
      />
      {!isProcess && (
        <Card>
          <div className="p-5">
            <SectionLabel>Triggering event</SectionLabel>
            <div className="mt-2">
              <KvRow label="Event type" mono>{dash(ev.event_type)}</KvRow>
              <KvRow label="Source" mono>{dash(ev.source_type)}</KvRow>
              <KvRow label="Host" mono>{dash(ev.hostname)}</KvRow>
              <KvRow label="Source IP" mono>{dash(ev.source_ip)}</KvRow>
              <KvRow label="Message">{dash(ev.message)}</KvRow>
            </div>
          </div>
        </Card>
      )}
      {hasParent && (
        <ProcessCard
          title="Parent process"
          name={basename(kvp.parent_image)}
          cmdline={kvp.parent_command_line}
          path={kvp.parent_image}
          pid={kvp.parent_process_id}
          user={kvp.parent_user}
          signer={kvp.parent_image && kvp.parent_image.toLowerCase().startsWith('c:\\windows\\') ? 'Microsoft Windows' : '-'}
        />
      )}

      {/* Triage actions (reversible; no confirm needed) */}
      <Card>
        <div className="p-5 flex flex-wrap items-center gap-2">
          <SectionLabel>Triage</SectionLabel>
          <div className="ml-auto flex items-center gap-2">
            <button
              type="button"
              onClick={() => doAction('promote')}
              className={`px-3 py-1.5 text-sm font-medium rounded-md border transition ${
                det.player_action === 'promoted' ? 'bg-[#101218] text-white border-transparent' : 'bg-white text-[#1a2332] border-[#d0d7de] hover:bg-[#eef1f4]'
              }`}
            >
              Promote to Threat
            </button>
            <button
              type="button"
              onClick={() => doAction('dismiss')}
              className={`px-3 py-1.5 text-sm font-medium rounded-md border transition ${
                det.player_action === 'dismissed' ? 'bg-[#57606a] text-white border-transparent' : 'bg-white text-[#1a2332] border-[#d0d7de] hover:bg-[#eef1f4]'
              }`}
            >
              Dismiss
            </button>
            {det.player_action !== 'open' && (
              <button type="button" onClick={() => doAction('open')} className="px-3 py-1.5 text-sm font-medium rounded-md border bg-white text-[#57606a] border-[#d0d7de] hover:bg-[#eef1f4] transition">
                Reopen
              </button>
            )}
          </div>
        </div>
      </Card>
    </div>
  );
};

export default DetectionDetail;
