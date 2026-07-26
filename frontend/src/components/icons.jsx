import React from 'react';
import {
  LayoutDashboard, Siren, ScanSearch, Crosshair, Monitor, ShieldCheck,
  LineChart, BookOpen, RotateCcw, Play, Server, Laptop, Apple, Ghost,
} from 'lucide-react';

// ============================================================================
// Visual pass V2: the ONE icon system.
//
// UI icons come from lucide-react (already installed; audited before any
// dependency question arose) -- one family, consistent stroke geometry.
// Uniform optical size: navigation renders at 19px, inline identity marks
// at 16px, all at strokeWidth 1.75 (matching the existing rail weight).
// No emoji anywhere. Icons are decorative by default (aria-hidden) --
// the accessible name always lives on the control or an explicit label;
// platform badges are the exception (role="img" + aria-label, because the
// badge IS the information).
//
// Brand/platform glyphs: lucide carries Apple; it has no Windows or Linux
// brand mark. Rather than adding a brand-icon dependency for two glyphs,
// the Windows four-pane mark (already hand-drawn in this repo, moved here
// from Endpoints.jsx) and a minimal penguin silhouette are local SVGs
// drawn to the same 24-unit grid. (Reported in the V2 inventory: the
// installed system lacks brand icons; two local glyphs beat a dependency.)
// ============================================================================

export const NAV_STROKE = 1.75;

// The ruled navigation identity map (V2): every primary destination has a
// DISTINCT identity -- the old rail shared one triangle between Incidents
// and Detections.
export const NAV_ICONS = {
  dashboard: LayoutDashboard,   // analytic overview grid
  incidents: Siren,             // the case queue
  siem: ScanSearch,             // log search workbench
  detections: Crosshair,        // triage queue
  endpoints: Monitor,           // asset explorer
  response: ShieldCheck,        // action command center
  analytics: LineChart,         // Metrics / Learning Review
};

// Chrome-level icons (rail footer + utility region).
export const ChromeIcons = { BookOpen, RotateCcw, Play, Ghost };

// One nav/page glyph: uniform size + stroke, decorative by default.
export const NavGlyph = ({ view, size = 19, className = '', ...rest }) => {
  const Icon = NAV_ICONS[view];
  if (!Icon) return null;
  return <Icon size={size} strokeWidth={NAV_STROKE} aria-hidden="true" className={className} {...rest} />;
};

// ---- platform / device identity (V2, consumed by V7/V9 surfaces) -----------

// The Windows four-pane mark (filled brand glyph, local).
export const WindowsGlyph = ({ size = 14, className = '', label = 'Windows' }) => (
  <svg
    role="img"
    aria-label={label}
    width={size}
    height={size}
    className={className}
    viewBox="0 0 24 24"
    fill="currentColor"
  >
    <path d="M3 5.1l7.4-1v7.3H3V5.1zm8.4-1.2L21 2.5v8.9h-9.6V3.9zM3 12.6h7.4v7.3L3 18.9v-6.3zm8.4 0H21v8.9l-9.6-1.4v-7.5z" />
  </svg>
);

// A minimal penguin silhouette for Linux (filled, local, 24-unit grid).
export const LinuxGlyph = ({ size = 14, className = '', label = 'Linux' }) => (
  <svg
    role="img"
    aria-label={label}
    width={size}
    height={size}
    className={className}
    viewBox="0 0 24 24"
    fill="currentColor"
  >
    <path
      fillRule="evenodd"
      d="M12 2c-2.5 0-4.1 1.9-4.1 4.4 0 1.1-.3 2.1-.9 3.3-.8 1.6-1.7 3.4-1.7 5.3 0 1.5.5 2.9 1.5 3.9-.7.4-1.1 1-1.1 1.6 0 1.1 1.3 1.8 3 1.8 1 0 1.9-.2 2.5-.6h1.6c.6.4 1.5.6 2.5.6 1.7 0 3-.7 3-1.8 0-.6-.4-1.2-1.1-1.6 1-1 1.5-2.4 1.5-3.9 0-1.9-.9-3.7-1.7-5.3-.6-1.2-.9-2.2-.9-3.3C16.1 3.9 14.5 2 12 2zm-1.6 4.7a.8.8 0 110 1.6.8.8 0 010-1.6zm3.2 0a.8.8 0 110 1.6.8.8 0 010-1.6zM12 8.6l1.3 1c.2.2.2.5 0 .6l-1 .6a.6.6 0 01-.6 0l-1-.6a.4.4 0 010-.6l1.3-1z"
    />
  </svg>
);

// The mapping from the REAL endpoint fields to a presentation identity.
// `platform` is the serialized snapshot field (today always 'windows' for
// managed hosts); os/role only refine device class or cover rows that
// carry no platform (network devices). Never guesses a brand the data
// does not state: anything unrecognized is 'unknown' with NO brand badge.
export const platformFor = ({ platform, os = '', role = '' } = {}) => {
  const p = String(platform || '').toLowerCase();
  const o = String(os || '').toLowerCase();
  const platformKey =
    p === 'windows' || (!p && o.includes('windows')) ? 'windows'
      : p === 'macos' || o.includes('macos') || o.includes('mac os') ? 'macos'
        : p === 'linux' || o.includes('linux') || o.includes('ubuntu') || o.includes('debian') ? 'linux'
          : 'unknown';
  const serverRoles = ['dc', 'file', 'dns', 'print', 'web', 'backup', 'scanner', 'server', 'proxy'];
  const isServer = o.includes('server')
    || (!!role && serverRoles.includes(String(role).toLowerCase()));
  const deviceKind = platformKey === 'unknown' ? 'unknown'
    : isServer ? 'server'
      : platformKey === 'macos' && o.includes('book') ? 'laptop'
        : 'workstation';
  return { platformKey, deviceKind };
};

const DEVICE_GLYPH = { server: Server, workstation: Monitor, laptop: Laptop, unknown: Monitor };
const PLATFORM_LABEL = { windows: 'Windows', macos: 'macOS', linux: 'Linux' };

// Device-class icon (decorative; pair it with the visible hostname).
export const DeviceGlyph = ({ deviceKind = 'unknown', size = 16, className = '', ...rest }) => {
  const Icon = DEVICE_GLYPH[deviceKind] || Monitor;
  return <Icon size={size} strokeWidth={NAV_STROKE} aria-hidden="true" className={className} {...rest} />;
};

// Platform brand badge: the informative mark (role=img + label). Unknown
// platforms render NOTHING -- never a guessed brand.
export const PlatformBadge = ({ platformKey = 'unknown', size = 14, className = '' }) => {
  if (platformKey === 'windows') return <WindowsGlyph size={size} className={className} />;
  if (platformKey === 'macos') {
    return <Apple size={size} strokeWidth={NAV_STROKE} role="img" aria-label={PLATFORM_LABEL.macos} className={className} />;
  }
  if (platformKey === 'linux') return <LinuxGlyph size={size} className={className} />;
  return null;
};

// One composed identity mark: device icon + platform badge, from the raw
// endpoint fields. The same mapping everywhere it appears (endpoint list,
// endpoint detail header, Response target rows, related-host identity).
export const HostIdentity = ({ platform, os, role, size = 16, className = '' }) => {
  const { platformKey, deviceKind } = platformFor({ platform, os, role });
  return (
    <span className={`inline-flex items-center gap-1 ${className}`}>
      <DeviceGlyph deviceKind={deviceKind} size={size} />
      <PlatformBadge platformKey={platformKey} size={Math.max(11, size - 3)} />
    </span>
  );
};
