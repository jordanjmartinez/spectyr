import React from 'react';

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

// Severity pill tints (Detections feed rows).
export const SEVERITY_PILL = {
  critical: 'bg-red-50 text-red-700 border-red-200',
  high: 'bg-orange-50 text-orange-700 border-orange-200',
  medium: 'bg-amber-50 text-amber-700 border-amber-200',
};

// Letter-grade color (display only; grades themselves are always
// server-computed).
export const gradeColor = (g) =>
  (!g || g === '-') ? '#8b949e'
    : g === 'F' ? '#b45858'
      : g === 'D' ? '#c08a3e'
        : '#6fa868';

// ---- surfaces ---------------------------------------------------------------

// The standard card. `hairline` stamps the page-identity gradient across
// the top (page headers and modals use it; plain content cards do not).
export const Card = ({ hairline = false, className = '', style, children }) => (
  <div className={`rounded-xl overflow-hidden ${className}`} style={{ ...CARD_STYLE, ...style }}>
    {hairline && <div className="h-0.5" style={{ background: HAIRLINE }} />}
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
        {subtitle && <p className="text-sm text-[#57606a] truncate">{subtitle}</p>}
      </div>
      {right && <div className="ml-auto flex flex-wrap items-center gap-2">{right}</div>}
    </div>
  </Card>
);

// ---- small identity pieces --------------------------------------------------

export const CountPill = ({ children }) => (
  <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-[#eef1f4] text-[#57606a]">{children}</span>
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
  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-[#eef1f4] text-[#57606a]">{children}</span>
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
          value === key ? 'bg-[#101218] text-white' : 'bg-white text-[#57606a] hover:bg-[#eef1f4]'
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
  secondary: 'bg-white text-[#57606a] border-[#d0d7de] hover:bg-[#eef1f4]',
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
  <p className="p-4 py-8 text-sm text-[#8b949e] text-center">{children}</p>
);

export const LoadingState = ({ children = 'Loading' }) => (
  <p className="p-4 py-8 text-sm text-[#8b949e] text-center">{children}</p>
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
