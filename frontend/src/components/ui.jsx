import React from 'react';
import { MODE_LABEL } from './uiCopy';

// ============================================================================
// Visual pass VG: the ONE shared visual-language module.
//
// Every tab consumes these tokens and primitives; no page defines its own
// copy of a color map, card surface, badge, or state treatment (the
// "solve it once" rule). Uniformity applies to the visual language and
// interaction conventions ONLY -- each workspace keeps the information
// architecture its function needs (Dashboard = overview grid, Incidents =
// master-detail, SIEM = query workbench, Detections = triage queue,
// Endpoints = asset explorer, Response = action command center, Metrics =
// Learning Review home).
//
// Tokens (named in tailwind.config.js for class use):
//   ink     #101218  dark chrome (rail, dark buttons, table heads)
//   body    #1a2332  primary text
//   dim     #57606a  secondary text
//   muted   #6e7781  section labels
//   faint   #8b949e  tertiary/empty text
//   edge    #e2e6ea  card borders          ctrl #d0d7de  control borders
//   seam    #eef1f4  dividers/soft fills   canvas #f6f8fa  app background
//   accent  #16436b  the ONE accent (INC links, hairline start)
//   ok / warn / danger reserved for STATE MEANING (severity, outcomes,
//   grades) -- never decoration (the standing accent-restraint rule).
//
// Breakpoints follow Tailwind defaults; the app's conventions:
//   sm 640px  = the phone/desktop type+padding step
//   lg 1024px = the rail-expands / two-pane / supporting-column step
// ============================================================================

export const COLORS = {
  ink: '#101218', inkHover: '#1e2330', body: '#1a2332', dim: '#57606a',
  muted: '#6e7781', faint: '#8b949e', edge: '#e2e6ea', ctrl: '#d0d7de',
  seam: '#eef1f4', canvas: '#f6f8fa', accent: '#16436b',
  ok: '#6fa868', warn: '#c08a3e', caution: '#c0a93e', danger: '#b45858',
};

// The standard card surface (kept as a style object because several
// legacy call sites splice it into `style=`; Card below is the primitive).
export const CARD_STYLE = {
  background: '#ffffff',
  border: '1px solid #e2e6ea',
  boxShadow: '0 1px 2px rgba(0,0,0,0.04)',
};

// The page-identity hairline (accent fading into ink).
export const HAIRLINE = 'linear-gradient(to right, #16436b, #101218)';

// ---- state color maps (the one definition each) -----------------------------

// Severity dots: ONE palette, case-insensitive keys (Incidents/Dashboard
// pass 'Critical', Detections passes 'critical').
export const SEVERITY_DOT = {
  critical: '#b45858', high: '#c08a3e', medium: '#c0a93e', low: '#6fa868',
};
export const severityDot = (sev) =>
  SEVERITY_DOT[String(sev || '').toLowerCase()] || '#8b949e';

// Severity pill tints (the one badge tint map; low deliberately keeps
// the neutral border + green dot the approved Detections feed shipped).
export const SEVERITY_PILL = {
  critical: 'bg-red-50 text-red-700 border-red-200',
  high: 'bg-orange-50 text-orange-700 border-orange-200',
  medium: 'bg-amber-50 text-amber-700 border-amber-200',
};

// ---- the shared incident identity system (VD2, reruled by VD8) --------------
// ONE treatment per concept, defined once and consumed everywhere. The
// three badges share ONE dimension contract (BADGE_BASE): Inter, 11px
// (owner sizing pass 2026-10-12: all pills slightly smaller, site-wide),
// medium weight, identical line-height / vertical padding / min-height /
// radius, ~20px tall, content vertically centered -- so the group
// [INC-1598] [Medium] [Guided] reads balanced on every surface.
//   IncidentIdBadge -- the incident identity. Owner card pass
//     (2026-10-12), superseding the neutral-ink ruling: the Spectr navy
//     fill with white ink; still INTER (no mono, no severity color).
//   SeverityBadge -- the approved Detections treatment as the source of
//     truth: direct label, restrained semantic tint, border + subtle
//     background, status dot; never color alone. Case-insensitive input
//     ('Critical' and 'critical' render identically).
//   ModeBadge -- identical metrics, per-mode fill (owner card pass
//     2026-10-12): Hardcore is the black pill; Guided / SOC Queue stay
//     the neutral light pill. Never a smaller tag (a transparent border
//     keeps the metrics identical).
//   IncidentIdentityRow -- the ONE canonical composition and order:
//     [INC id] [Severity] ([Mode]) then the title, wrapping naturally
//     (title drops to its own line when constrained; nothing shrinks or
//     clips to force one line).

export const BADGE_BASE = 'inline-flex items-center rounded-full text-[11px] font-medium leading-4 py-0.5 min-h-[20px] whitespace-nowrap shrink-0';

export const IncidentIdBadge = ({ id }) => (
  <span
    data-testid="incident-id-badge"
    className={`${BADGE_BASE} px-2 bg-[#16436b] text-white border border-[#16436b]`}
  >
    {id}
  </span>
);

export const SeverityBadge = ({ severity }) => {
  const k = String(severity || '').toLowerCase();
  return (
    <span
      data-testid="severity-badge"
      className={`${BADGE_BASE} px-2 gap-1.5 border ${
        SEVERITY_PILL[k] || 'border-[#d0d7de] text-muted'}`}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: severityDot(k) }} />
      {k ? k.charAt(0).toUpperCase() + k.slice(1) : ''}
    </span>
  );
};

// per-mode fill only; the metrics stay BADGE_BASE for every mode
const MODE_PILL = { hardcore: 'bg-[#101218] text-white' };

export const ModeBadge = ({ mode }) => (
  <span
    data-testid="mode-badge"
    className={`${BADGE_BASE} px-2 border border-transparent ${MODE_PILL[mode] || 'bg-[#eef1f4] text-muted'}`}
  >
    {MODE_LABEL[mode] || mode}
  </span>
);

export const IncidentIdentityRow = ({
  incidentId, severity, mode, title, titleClass = 'text-sm text-[#1a2332]',
}) => (
  <span className="inline-flex items-center gap-1.5 min-w-0 flex-wrap" data-testid="incident-pill">
    <IncidentIdBadge id={incidentId} />
    {severity && <SeverityBadge severity={severity} />}
    {mode && <ModeBadge mode={mode} />}
    {title && <span className={`${titleClass} min-w-0`}>{title}</span>}
  </span>
);

// Letter-grade color (display only; grades themselves are always
// server-computed).
export const gradeColor = (g) =>
  (!g || g === '-') ? '#8b949e'
    : g === 'F' ? '#b45858'
      : g === 'D' ? '#c08a3e'
        : '#6fa868';

// ---- surfaces ---------------------------------------------------------------

// The standard card. VP16 (owner correction): ordinary workspace cards
// carry the subtle border on ALL sides and NO dark top stripe -- the
// decorative accent is retired everywhere (`hairline` is accepted and
// ignored so no caller can reintroduce it; a strong top accent may
// return only when it communicates a real semantic state).
export const Card = ({ hairline = false, className = '', style, children }) => (
  <div className={`rounded-xl overflow-hidden ${className}`} style={{ ...CARD_STYLE, ...style }}>
    {children}
  </div>
);

// The standard page-identity card: icon tile + count + subtitle, with a
// right-hand slot for page-level controls (view toggles, search). VH
// (owner correction): the WORKSPACE TITLE lives in the one AppHeader
// above the content -- this card no longer repeats it (no stacked
// duplicate headers); the `title` prop remains accepted as the card's
// accessible name.
export const PageHeader = ({ icon, title, count = null, subtitle, right = null }) => (
  <Card hairline className="mb-4">
    <div className="p-4 sm:p-5 flex flex-wrap items-center gap-4" aria-label={title || undefined}>
      {icon && (
        <div className="w-10 h-10 rounded-lg bg-[#101218] flex items-center justify-center shrink-0 text-white">
          {icon}
        </div>
      )}
      <div className="min-w-0 flex items-center gap-2">
        {count !== null && <CountPill>{count}</CountPill>}
        {subtitle && <p className="text-sm text-muted truncate">{subtitle}</p>}
      </div>
      {right && <div className="ml-auto flex flex-wrap items-center gap-2">{right}</div>}
    </div>
  </Card>
);

// VA1 (amendment): the ONE page intro -- a concise functional subtitle,
// the active-incident context rendered EXACTLY ONCE as a compact pill,
// and the page controls. This replaces both the large secondary identity
// cards and the retired full-width "All activity" scope bars; there is no
// replacement status bar, and no page repeats the incident context.
// VC5 (owner instruction): the functional page summary moved into the
// unified AppHeader, on its own line under the section header. This row
// keeps ONLY the incident-context identity row and the page controls;
// it renders nothing when it has neither.
export const PageIntro = ({ incident = null, right = null }) => (
  (incident?.incidentId || right) ? (
    <div className="mb-4 flex flex-wrap items-center gap-x-4 gap-y-2">
      {incident?.incidentId && <IncidentIdentityRow {...incident} />}
      {right && <div className="ml-auto flex flex-wrap items-center gap-2">{right}</div>}
    </div>
  ) : null
);

// Owner list-page uniformity (2026-10-12): the ONE toolbar search input
// shared by the list pages (Incidents, Detections, Endpoints) -- the
// toolbar pattern is status tabs with counts (SegmentedToggle) plus this
// search, in the PageIntro right slot.
export const ToolbarSearch = ({ value, onChange, placeholder }) => (
  <input
    type="text"
    value={value}
    onChange={(e) => onChange(e.target.value)}
    placeholder={placeholder}
    className="w-full sm:w-56 px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] bg-white text-[#1a2332] placeholder-[#8b949e] focus:outline-none focus:ring-2 focus:ring-[#101218]/20"
  />
);

// ---- small identity pieces --------------------------------------------------

export const CountPill = ({ children }) => (
  <span className="px-1.5 py-0.5 rounded-full text-[11px] font-medium bg-[#eef1f4] text-muted">{children}</span>
);

export const SectionLabel = ({ className = '', children }) => (
  <p className={`t-overline ${className}`}>{children}</p>
);

export const Dot = ({ color }) => (
  <span aria-hidden="true" className="w-1.5 h-1.5 rounded-full shrink-0 inline-block" style={{ background: color }} />
);

export const SeverityDotMark = ({ severity }) => <Dot color={severityDot(severity)} />;

// Neutral state chip (factual observable state on targets/rows).
export const StateChip = ({ children }) => (
  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-[#eef1f4] text-muted">{children}</span>
);

// ---- the ONE horizontal bar list ---------------------------------------------
// Owner unification (2026-10-12): Evidence Activity and Severity
// Distribution render the SAME row anatomy -- muted text-sm label, h-2
// track in #eef1f4 capped at 10rem, right-aligned font-medium tabular
// count -- differing ONLY in fill color (and the label column width, a
// per-card layout necessity for long source names vs short severities).
export const BarList = ({ children }) => (
  <div className="space-y-1.5">{children}</div>
);

export const BarRow = ({ label, count, max, fill, labelWidth = 'w-32', testid = null }) => (
  <div className="flex items-center gap-2 text-sm" data-testid={testid || undefined}>
    <span className={`${labelWidth} shrink-0 text-muted`}>{label}</span>
    <span className="flex-1 max-w-[10rem] h-2 rounded-full bg-[#eef1f4] overflow-hidden" aria-hidden="true">
      <span
        data-testid={testid ? `${testid}-bar` : undefined}
        className="block h-full rounded-full"
        style={{ width: `${max ? (count / max) * 100 : 0}%`, background: fill }}
      />
    </span>
    <span className="w-8 shrink-0 text-right font-medium text-[#1a2332] tabular-nums">{count}</span>
  </div>
);

// ---- controls ---------------------------------------------------------------

// The standard segmented view toggle (Cards/Table, Actions/Response Log,
// Active/Ready/Completed...). options = [[key, label], ...].
export const SegmentedToggle = ({ options, value, onChange, ariaLabel }) => (
  <div className="inline-flex items-center rounded-md border border-[#d0d7de] overflow-hidden" role="group" aria-label={ariaLabel}>
    {options.map(([key, label]) => (
      <button
        key={key}
        type="button"
        onClick={() => onChange(key)}
        className={`px-3 py-1.5 text-xs font-medium transition ${
          value === key ? 'bg-[#101218] text-white' : 'bg-white text-muted hover:bg-[#eef1f4]'
        }`}
      >
        {label}
      </button>
    ))}
  </div>
);

// The three button voices. `primary` = the one committing action on a
// surface; `secondary` = neutral; `accent` = navigation into another
// workspace (never executes anything).
const BTN_VARIANTS = {
  primary: 'bg-[#101218] text-white border-transparent hover:bg-[#1e2330]',
  secondary: 'bg-white text-muted border-[#d0d7de] hover:bg-[#eef1f4]',
  accent: 'bg-transparent text-[#16436b] border-[#16436b]/40 hover:bg-[#16436b]/5',
};
export const Btn = ({ variant = 'secondary', className = '', type = 'button', children, ...rest }) => (
  <button
    type={type}
    className={`px-3 py-1.5 text-sm font-medium rounded-md border transition disabled:opacity-50 disabled:cursor-default ${BTN_VARIANTS[variant]} ${className}`}
    {...rest}
  >
    {children}
  </button>
);

// ---- shared page states -----------------------------------------------------

export const EmptyState = ({ children }) => (
  <p className="p-4 py-8 text-sm text-muted text-center">{children}</p>
);

export const LoadingState = ({ children = 'Loading' }) => (
  <p className="p-4 py-8 text-sm text-muted text-center">{children}</p>
);

export const ErrorState = ({ children, onRetry = null }) => (
  <div role="alert" className="p-4 py-6 text-sm text-[#1a2332] text-center">
    {children}
    {onRetry && (
      <button
        type="button"
        onClick={onRetry}
        className="ml-2 px-2 py-0.5 rounded border border-[#d0d7de] bg-white text-[#1a2332]"
      >
        Retry
      </button>
    )}
  </div>
);
