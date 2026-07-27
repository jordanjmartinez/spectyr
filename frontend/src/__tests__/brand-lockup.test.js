/**
 * VB2 + VC2 + VC3 (final lockup correction): the SPECTR brand lockup.
 * A VISIBLE branding change only -- the ghost mark stays the symbol, the
 * wordmark is uppercase in the shared .brand-wordmark display face
 * (Bank-Gothic-like, already loaded, LOGO ONLY -- it never spreads to
 * product type), the app shell and BOTH Docs shells render the ONE
 * shared BrandLockup component at the same full size (no smaller Docs
 * variant, no rem-drifting nav-label sizes), and NO internal identifier
 * (asset filename, storage key, API path, package name, scenario
 * content) is renamed. Page titles keep their existing forms.
 */
import fs from 'fs';
import path from 'path';

const SRC = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(SRC, rel), 'utf8');
const html = fs.readFileSync(path.join(SRC, '..', 'public', 'index.html'), 'utf8');

// files allowed to reference the display-face class: the one shared
// component + the marketing/loading surfaces that render the wordmark
// at their own contextual sizes (the landing hero is text-only: its 3D
// ghost is the page's mark)
const FACE_USERS = ['components/BrandLockup.jsx', 'App.jsx', 'components/Navbar.jsx',
                    'pages/Landing.jsx'];
// shells that must render the shared component (never a local lockup)
const SHELLS = ['pages/Dashboard.jsx', 'pages/Docs.jsx'];

test('every prominent shell renders the shared SPECTR lockup; the old label is gone', () => {
  expect(read('components/BrandLockup.jsx')).toMatch(/>\s*SPECTR\s*</);
  for (const f of SHELLS) {
    const s = read(f);
    expect([f, /<BrandLockup/.test(s)]).toEqual([f, true]);
    // no shell keeps a local ghost <img> lockup beside the component
    expect([f, /spectyr_logo\.png/.test(s)]).toEqual([f, false]);
  }
  for (const f of [...SHELLS, ...FACE_USERS]) {
    // the old wordmark no longer renders as a lockup label anywhere
    expect([f, />\s*Spectyr\s*</.test(read(f))]).toEqual([f, false]);
  }
  // the sim app + Docs desktop + Docs mobile all use it (1 + 2 sites)
  expect((read('pages/Dashboard.jsx').match(/<BrandLockup/g) || []).length).toBe(1);
  expect((read('pages/Docs.jsx').match(/<BrandLockup/g) || []).length).toBe(2);
});

test('the wordmark face is already loaded: no new font dependency, no font binaries', () => {
  // VC2: Bank Gothic itself is unlicensed here and is NOT bundled; the
  // wordmark uses Orbitron from the existing approved font link
  expect(html).toMatch(/family=Orbitron/);
  const css = read('index.css');
  const rule = css.match(/\.brand-wordmark\s*{[^}]*}/)[0];
  expect(rule).toMatch(/font-family:\s*'Orbitron', 'Inter', sans-serif/);
  expect(rule).toMatch(/font-weight:\s*500/);          // medium, not gamer-heavy
  expect(rule).toMatch(/line-height:\s*1;/);           // VC3: lockup line-height 1
  const tracking = parseFloat(rule.match(/letter-spacing:\s*([\d.]+)em/)[1]);
  expect(tracking).toBeLessThanOrEqual(0.06);          // restrained for a wide face
  // Inter remains the product UI font (body stack unchanged)
  expect(css).toMatch(/body\s*{[^}]*font-family:\s*'Inter'/);
  // JetBrains Mono stays the technical-value face (tokens unchanged)
  expect(css).toMatch(/\.log-mono\s*{\s*font-family:\s*'JetBrains Mono'/);
  // no font binaries were added for the wordmark (JetBrains Mono only)
  const fontsDir = path.join(SRC, 'fonts');
  expect(fs.readdirSync(fontsDir).filter((f) => !/^JetBrainsMono-/.test(f))).toEqual([]);
});

test('the display face is scoped to the SPECTR wordmark only', () => {
  // walk the source tree: the brand class appears only in the known
  // lockup files (styling the SPECTR text), and the face name appears in
  // no source file beyond the one index.css brand rule
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) return ['__tests__', 'fonts'].includes(e.name) ? [] : walk(p);
    return /\.(js|jsx|css)$/.test(e.name) ? [p] : [];
  });
  for (const p of walk(SRC)) {
    const rel = path.relative(SRC, p).replace(/\\/g, '/');
    const s = fs.readFileSync(p, 'utf8');
    if (rel !== 'index.css') {
      expect([rel, /Orbitron/.test(s)]).toEqual([rel, false]);
    }
    const uses = (s.match(/brand-wordmark/g) || []).length;
    if (uses && rel !== 'index.css') {
      expect([rel, FACE_USERS.includes(rel)]).toEqual([rel, true]);
      // within a lockup file the class never outnumbers SPECTR renders
      expect(uses).toBeLessThanOrEqual((s.match(/SPECTR/g) || []).length);
    }
  }
});

test('ONE shared lockup at the ruled size: 72px ghost + 30px wordmark, shrink-proof, unclipped', () => {
  const c = read('components/BrandLockup.jsx');
  // px-FIXED dimensions (VC3 sections 3+5; VC4 doubled the ghost per the
  // owner's "at least double" instruction, VC6 trimmed it "a tad" to
  // 72px on the follow-up): never rem/nav-label derived
  expect(c).toMatch(/h-\[72px\] w-\[72px\][^"]*object-contain[^"]*shrink-0/);
  expect(c).toMatch(/brand-wordmark text-\[30px\][^"]*shrink-0/);
  // no transform-based scaling, no max-height shrinking, no clipping --
  // judged on the rendered class strings, not prose comments
  const classes = [...c.matchAll(/className=\{?["'`]([^"'`]+)["'`]/g)].map((m) => m[1]).join(' ');
  expect(classes).not.toMatch(/scale-|transform|rotate-/);
  expect(classes).not.toMatch(/max-h-/);
  expect(classes).toMatch(/max-w-none/); // defuses the preflight img max-width
  expect(classes).not.toMatch(/overflow-hidden|truncate/);
  // the mark is decorative; text carries the name
  expect(c).toMatch(/spectyr_logo\.png"\s+alt=""\s+aria-hidden="true"/);
});

test('the sidebar lockup is a real destination with an accessible name, never a dead control', () => {
  const rail = read('pages/Dashboard.jsx');
  expect(rail).toMatch(/SPECTR home/);
  // it keeps the app's existing home navigation (not a new behavior)
  expect(rail).toMatch(/<Link\s+to="\/"/);
  // the branded top area is the sidebar cell of the unified shell row
  // (VC1; 96px since VC4 to carry the 80px ghost), divider retained
  expect(rail).toMatch(/h-\[96px\][^"]*border-b border-white\/10/);
});

test('internal identifiers are NOT renamed by this visible-brand change', () => {
  // asset filenames, storage keys, API paths, and package name stay
  expect(read('components/BrandLockup.jsx')).toMatch(/spectyr_logo\.png/);
  expect(read('api.js')).toMatch(/spectyr_session/);
  const pkg = JSON.parse(fs.readFileSync(path.join(SRC, '..', 'package.json'), 'utf8'));
  expect(pkg.name).toBe('frontend');
  // scenario content keeps its authored identifiers
  expect(read('__tests__/detections.test.js')).toMatch(/Spectyr_USB_Loader_Generic/);
});

test('page titles keep their existing forms (no uppercased prose or titles)', () => {
  const dash = read('pages/Dashboard.jsx');
  for (const label of ['Dashboard', 'Incidents', 'SIEM', 'Detections',
                       'Endpoints', 'Response', 'Metrics']) {
    expect([label, dash.includes(`label: '${label}'`)]).toEqual([label, true]);
  }
  // SPECTR appears only as branding, never as a page title entry
  expect(dash).not.toMatch(/label: 'SPECTR'/);
});
