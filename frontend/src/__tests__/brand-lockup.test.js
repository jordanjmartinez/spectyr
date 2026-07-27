/**
 * VB2 + VC2 (header correction sections 3-4): the SPECTR brand lockup.
 * A VISIBLE branding change only -- the ghost mark stays the symbol, the
 * wordmark is uppercase in the shared .brand-wordmark display face
 * (Bank-Gothic-like Orbitron, already loaded, LOGO ONLY -- it never
 * spreads to product type), and NO internal identifier (asset filename,
 * storage key, API path, package name, scenario content) is renamed.
 * Page titles keep their existing forms.
 */
import fs from 'fs';
import path from 'path';

const SRC = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(SRC, rel), 'utf8');
const html = fs.readFileSync(path.join(SRC, '..', 'public', 'index.html'), 'utf8');

const LOCKUPS = ['pages/Dashboard.jsx', 'App.jsx', 'components/Navbar.jsx', 'pages/Docs.jsx'];

test('every prominent shell lockup renders the SPECTR wordmark', () => {
  for (const f of LOCKUPS) {
    const s = read(f);
    expect([f, s.includes('SPECTR')]).toEqual([f, true]);
    // the old wordmark no longer renders as a lockup label
    expect([f, />\s*Spectyr\s*</.test(s)]).toEqual([f, false]);
  }
});

test('the wordmark face is already loaded: no new font dependency, no font binaries', () => {
  // VC2: Bank Gothic itself is unlicensed here and is NOT bundled; the
  // wordmark uses Orbitron from the existing approved font link
  expect(html).toMatch(/family=Orbitron/);
  const css = read('index.css');
  const rule = css.match(/\.brand-wordmark\s*{[^}]*}/)[0];
  expect(rule).toMatch(/font-family:\s*'Orbitron', 'Inter', sans-serif/);
  expect(rule).toMatch(/font-weight:\s*500/);          // medium, not gamer-heavy
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
      expect([rel, LOCKUPS.includes(rel)]).toEqual([rel, true]);
      // within a lockup file the class never outnumbers SPECTR renders
      expect(uses).toBeLessThanOrEqual((s.match(/SPECTR/g) || []).length);
    }
  }
});

test('the sidebar lockup is a real destination with an accessible name, never a dead control', () => {
  const rail = read('pages/Dashboard.jsx');
  // the mark is decorative; the accessible name comes from text
  expect(rail).toMatch(/spectyr_logo\.png" alt="" aria-hidden="true"/);
  expect(rail).toMatch(/SPECTR home/);
  // it keeps the app's existing home navigation (not a new behavior)
  expect(rail).toMatch(/<Link\s+to="\/"/);
  // the branded top area is the sidebar cell of the unified 72px shell
  // row (VC1), with the divider retained
  expect(rail).toMatch(/h-\[72px\][^"]*border-b border-white\/10/);
  // VC2 (section 4 scale): the 32px ghost + 28px wordmark read as one
  // designed lockup, not a navigation label
  expect(rail).toMatch(/h-8 w-8 object-contain/);
  expect(rail).toMatch(/brand-wordmark text-\[28px\]/);
});

test('internal identifiers are NOT renamed by this visible-brand change', () => {
  // asset filenames, storage keys, API paths, and package name stay
  expect(read('pages/Dashboard.jsx')).toMatch(/spectyr_logo\.png/);
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
