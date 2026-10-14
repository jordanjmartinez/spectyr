import React, { useState, useEffect } from 'react';
import { apiFetch } from '../api';
import { SeverityBadge } from './ui';
import { DispositionChip } from './Detections';
import {
  PROMOTE_ACTION, PROMOTE_HELPER, DISMISS_ACTION, DISMISS_HELPER, REOPEN_ACTION,
  DET_WHY_TITLE, DET_HARMLESS_LABEL, DET_RULE_TITLE, DET_METHOD_LABEL,
  DET_METHOD_SIGMA, DET_METHOD_SIGMA_GLOSS, DET_METHOD_YARA, DET_METHOD_YARA_GLOSS,
  DET_ID_LABEL, DET_ENTITY_TITLE, DET_TRIGGER_TITLE, DET_MITRE_TITLE, DET_CHECKS_TITLE,
} from './uiCopy';

// Detection detail (Stage 2), the Section 8 card anatomy: lineage as
// first-class UI. Triggering Event card plus a stacked Parent Process card.
// SHA256 is fictional and shown with a copy button, never a VirusTotal link.
//
// Decision-layer pass (owner 2026-10-13): the page reads top-down as a
// decision. Header = severity + rule name + (timestamp, host, user); the
// Sigma pill and the raw detection id left the header. A STICKY triage bar
// carries the two decisions with one-line helpers (the bottom Triage card
// is gone). Body order: Why This Fired (the server-composed instance line
// + the rule's "when this can be harmless" line) -> What the Rule Detects
// (description, glossed detection method, the copyable Detection ID small
// and muted at its foot) -> Affected Entity -> Triggering Event (+ parent
// lineage) -> MITRE ATT&CK (technique name first, tactic as context, one
// plain gloss) -> What to Check (the rule's 3-5 step list). Every teaching
// string is per-RULE or per-INSTANCE-observable; none carries a verdict.

const basename = (p) => (p ? p.split('\\').pop().split('/').pop() : '');
const dash = (v) => (v === null || v === undefined || v === '' ? '-' : v);

const SectionLabel = ({ children }) => (
  <p className="t-overline">{children}</p>
);

// Card headings render at the standard container-heading size
// (t-subsection, the VA3 "ONE primary container heading" token). The header
// card keeps its overline eyebrow; the rule name h2 is its heading.
const CardTitle = ({ children }) => (
  <p className="t-subsection">{children}</p>
);

const Card = ({ children, className = '' }) => (
  <div className={`bg-white border border-[#e2e6ea] rounded-xl overflow-hidden ${className}`}>
    {children}
  </div>
);

const SignatureBadge = ({ signer }) => (
  signer && signer !== '-' ? (
    <span className="inline-flex items-center px-1.5 py-0.5 rounded-full text-[11px] bg-emerald-50 text-emerald-700 border border-emerald-200" title={signer}>Signed</span>
  ) : (
    <span className="inline-flex items-center px-1.5 py-0.5 rounded-full text-[11px] bg-red-50 text-red-700 border border-red-200">Unsigned</span>
  )
);

const KvRow = ({ label, children, mono }) => (
  <div className="flex justify-between gap-3 py-2 border-b border-[#eef1f4] text-sm last:border-b-0">
    <span className="text-muted shrink-0">{label}</span>
    <span className={`text-[#1a2332] text-right break-all ${mono ? 'log-mono' : ''}`}>{children}</span>
  </div>
);

const useCopy = () => {
  const [copied, setCopied] = useState(false);
  const copy = (value) => {
    if (!value) return;
    try { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1200); } catch (e) { /* clipboard unavailable */ }
  };
  return [copied, copy];
};

// The triggering-event-plus-parent card stack. Renders reduced KV rows when a
// field is absent (e.g. non-process triggers like 1102 or DNS).
const ProcessCard = ({ title, name, cmdline, path, pid, ppid, signer, sha256, user }) => {
  const [copied, copy] = useCopy();
  return (
    <Card>
      <div className="p-5">
        <CardTitle>{title}</CardTitle>
        <h3 className="mt-1 log-mono text-lg font-semibold text-[#1a2332] break-all">{name || '-'}</h3>
        {cmdline && (
          <pre className="mt-3 p-3 rounded-lg bg-[#f6f8fa] border border-[#eef1f4] text-xs log-mono text-[#1a2332] overflow-x-auto whitespace-pre-wrap break-all">{cmdline}</pre>
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
                <span className="log-mono text-xs break-all">{dash(sha256)}</span>
                {sha256 && (
                  <button type="button" onClick={() => copy(sha256)} className="shrink-0 text-[#16436b] hover:underline text-xs" aria-label="Copy SHA256">
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

// MITRE: "Technique Name (Txxxx)" first; the id alone when the pinned name
// is absent (older payloads); the tactic as context; one plain gloss.
export const mitreHeadline = (m) => (m?.name ? `${m.name} (${m.id})` : m?.id || '-');

const DetectionDetail = ({ detId, onBack, onAction, onHostPivot,
                           onEvidenceDescent, descentScopeIncidentId }) => {
  const [det, setDet] = useState(null);
  const [notFound, setNotFound] = useState(false);
  const [idCopied, copyId] = useCopy();

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
        <Card><div className="p-6 text-muted">This detection is no longer available.</div></Card>
      </div>
    );
  }
  if (!det) {
    return (
      <div>
        <button type="button" onClick={onBack} className="text-sm text-[#16436b] hover:underline mb-4">&larr; All detections</button>
        <p className="text-muted text-sm">Loading detection...</p>
      </div>
    );
  }

  const ev = (det.triggering_events || [])[0] || {};
  const kvp = ev.key_value_pairs || {};
  const isProcess = !!kvp.image;
  const hasParent = !!kvp.parent_image;
  const isYara = det.rule_type === 'yara';
  const guidance = det.guidance || {};
  const checks = Array.isArray(guidance.checks) ? guidance.checks : [];
  const hostNode = det.entity?.host ? (
    <button type="button" onClick={() => onHostPivot?.(det.entity.host)} className="text-[#16436b] hover:underline" title={`Open ${det.entity.host} in Endpoints`}>
      {det.entity.host}
    </button>
  ) : null;

  return (
    <div className="space-y-4">
      <button type="button" onClick={onBack} className="text-sm text-[#16436b] hover:underline">&larr; All detections</button>

      {/* Detection header: severity, rule name, the SIEM entry, then
          timestamp / host / user. No rule-type pill, no raw id. */}
      <Card>
        <div className="p-5">
          <div className="flex flex-wrap items-center gap-2">
            <SectionLabel>Detection</SectionLabel>
            <SeverityBadge severity={det.severity} />
          </div>
          <h2 className="mt-2 text-xl sm:text-2xl font-semibold text-[#1a2332]">{det.rule_name}</h2>
          {/* "Investigate in SIEM" (III.0 item 5 rename of the P7.2/P7.4
              entry; R17 uniform control -- never "View Triggering
              Evidence"). Prepares and opens the existing SIEM search
              anchored to the detection's OBSERVABLE ENTITY: host-entity
              detections prepare the host search, identity (account-entity)
              detections the account search. One control, one request
              grammar for every detection kind -- presence and content
              depend only on the visible entity, never on disposition,
              scenario membership, or any answer-key state. */}
          {(det.entity?.host || det.entity?.account) && onEvidenceDescent && (
            <div className="mt-2">
              <button
                type="button"
                onClick={() => onEvidenceDescent({
                  hosts: det.entity.host ? [det.entity.host] : [],
                  account: det.entity.host ? null : det.entity.account,
                  scopeIncidentId: descentScopeIncidentId || null,
                })}
                className="text-xs font-medium text-[#16436b] hover:underline"
              >
                Investigate in SIEM
              </button>
            </div>
          )}
          <p className="mt-1 text-sm text-muted log-mono">
            {det.time ? det.time.slice(0, 19).replace('T', ' ') : '-'}
            {' '}&middot;{' '}
            {hostNode || (det.entity?.account && !det.entity?.host ? (
              <span className="text-muted" title="Identity entity (no endpoint)">{det.entity.account}</span>
            ) : '-')}
            {det.entity?.host && det.entity?.account && (
              <>{' '}&middot;{' '}<span className="text-muted">{det.entity.account}</span></>
            )}
          </p>
        </div>
      </Card>

      {/* The sticky triage bar: the two decisions with their helpers. Open
          offers Promote to Threat / Dismiss as Benign; a reviewed detection
          reads STATE + Reopen, the one way back (Stage 6 fix 13 shape). */}
      <div className="sticky top-0 z-10" data-testid="triage-bar">
        <Card className="shadow-sm">
          <div className="p-4 flex flex-wrap items-stretch gap-3">
            {det.player_action === 'open' ? (
              <>
                <div className="flex flex-col gap-1 min-w-[12rem]">
                  <button
                    type="button"
                    onClick={() => doAction('promote')}
                    className="px-3 py-1.5 text-sm font-medium rounded-md border transition bg-[#101218] text-white border-[#101218] hover:bg-[#1a2332]"
                  >
                    {PROMOTE_ACTION}
                  </button>
                  <span className="text-xs text-muted">{PROMOTE_HELPER}</span>
                </div>
                <div className="flex flex-col gap-1 min-w-[12rem]">
                  <button
                    type="button"
                    onClick={() => doAction('dismiss')}
                    className="px-3 py-1.5 text-sm font-medium rounded-md border transition bg-white text-[#1a2332] border-[#d0d7de] hover:bg-[#eef1f4]"
                  >
                    {DISMISS_ACTION}
                  </button>
                  <span className="text-xs text-muted">{DISMISS_HELPER}</span>
                </div>
              </>
            ) : (
              <div className="flex items-center gap-2">
                <DispositionChip action={det.player_action} size="sm" />
                <button type="button" onClick={() => doAction('open')} className="px-3 py-1.5 text-sm font-medium rounded-md border bg-white text-muted border-[#d0d7de] hover:bg-[#eef1f4] transition">
                  {REOPEN_ACTION}
                </button>
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* 1. Why this fired: the instance line + the rule's harmless line */}
      <Card>
        <div className="p-5">
          <CardTitle>{DET_WHY_TITLE}</CardTitle>
          <p className="mt-1.5 text-sm text-[#1a2332] leading-relaxed">{det.why || dash(det.why)}</p>
          {guidance.harmless && (
            <p className="mt-2 text-sm text-muted leading-relaxed">
              <span className="font-medium text-[#1a2332]">{DET_HARMLESS_LABEL}:</span>{' '}{guidance.harmless}
            </p>
          )}
        </div>
      </Card>

      {/* 2. What the rule detects: the authored description, the glossed
          detection method, the Detection ID small and muted at the foot */}
      <Card>
        <div className="p-5">
          <CardTitle>{DET_RULE_TITLE}</CardTitle>
          <p className="mt-1.5 text-sm text-[#1a2332] leading-relaxed">{det.description}</p>
          <p className="mt-2 text-sm text-muted">
            <span className="font-medium text-[#1a2332]">{DET_METHOD_LABEL}:</span>{' '}
            {isYara ? DET_METHOD_YARA : DET_METHOD_SIGMA}
            <span className="text-muted">, {isYara ? DET_METHOD_YARA_GLOSS : DET_METHOD_SIGMA_GLOSS}</span>
            {det.yara_rule_name && (
              <>{' '}&middot;{' '}<span className="log-mono text-xs">{det.yara_rule_name}</span></>
            )}
          </p>
          <p className="mt-3 pt-3 border-t border-[#eef1f4] text-xs text-muted">
            {DET_ID_LABEL}{' '}
            <span className="log-mono">{det.id}</span>
            {' '}
            <button type="button" onClick={() => copyId(det.id)} className="text-[#16436b] hover:underline" aria-label="Copy detection ID">
              {idCopied ? 'Copied' : 'Copy'}
            </button>
          </p>
        </div>
      </Card>

      {/* 3. Affected entity */}
      <Card>
        <div className="p-5">
          <CardTitle>{DET_ENTITY_TITLE}</CardTitle>
          <div className="mt-2">
            <KvRow label="Host" mono>{hostNode || '-'}</KvRow>
            <KvRow label="User" mono>{dash(det.entity?.account)}</KvRow>
          </div>
        </div>
      </Card>

      {/* 4. Triggering event, then parent process: lineage as first-class UI */}
      <ProcessCard
        title={DET_TRIGGER_TITLE}
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
            <CardTitle>Event Details</CardTitle>
            <div className="mt-2">
              <KvRow label="Event type" mono>{dash(ev.event_type)}</KvRow>
              <KvRow label="Source" mono>{dash(ev.source_type)}</KvRow>
              <KvRow label="Hostname" mono>{dash(ev.hostname)}</KvRow>
              <KvRow label="Source IP" mono>{dash(ev.source_ip)}</KvRow>
              <KvRow label="Message">{dash(ev.message)}</KvRow>
            </div>
          </div>
        </Card>
      )}
      {hasParent && (
        <ProcessCard
          title="Parent Process"
          name={basename(kvp.parent_image)}
          cmdline={kvp.parent_command_line}
          path={kvp.parent_image}
          pid={kvp.parent_process_id}
          user={kvp.parent_user}
          signer={kvp.parent_image && kvp.parent_image.toLowerCase().startsWith('c:\\windows\\') ? 'Microsoft Windows' : '-'}
        />
      )}

      {/* 5. MITRE ATT&CK: technique name first, tactic as context, gloss */}
      {det.mitre && (
        <Card>
          <div className="p-5">
            <CardTitle>{DET_MITRE_TITLE}</CardTitle>
            <p className="mt-1.5 text-sm font-medium text-[#1a2332]">{mitreHeadline(det.mitre)}</p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <span className="text-xs text-muted">Tactic</span>
              <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs border border-[#d0d7de] text-muted">{det.mitre.tactic}</span>
            </div>
            {det.mitre.gloss && (
              <p className="mt-2 text-sm text-muted leading-relaxed">{det.mitre.gloss}</p>
            )}
          </div>
        </Card>
      )}

      {/* 6. What to check: the rule's 3-5 step list */}
      {checks.length > 0 && (
        <Card>
          <div className="p-5">
            <CardTitle>{DET_CHECKS_TITLE}</CardTitle>
            <ol className="mt-2 space-y-1.5 list-decimal pl-5 text-sm text-[#1a2332] leading-relaxed">
              {checks.map((c, i) => <li key={i}>{c}</li>)}
            </ol>
          </div>
        </Card>
      )}
    </div>
  );
};

export default DetectionDetail;
