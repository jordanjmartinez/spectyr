/**
 * VB2 (amendment sections 4-5): the SPECTR brand lockup. A VISIBLE
 * branding change only -- the ghost mark stays the symbol, the wordmark
 * is uppercase in an already-loaded display face, and NO internal
 * identifier (asset filename, storage key, API path, package name,
 * scenario content) is renamed. Page titles keep their existing forms.
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

test('the wordmark face is already loaded: no new font dependency, no shared font files', () => {
  // Space Grotesk ships in the existing approved font link
  expect(html).toMatch(/family=Space\+Grotesk/);
  const rail = read('pages/Dashboard.jsx');
  expect(rail).toMatch(/'Space Grotesk', 'Inter', sans-serif/);
  // Inter remains the product UI font (body stack unchanged)
  expect(read('index.css')).toMatch(/body\s*{[^}]*font-family:\s*'Inter'/);
  // no font binaries were added for the wordmark
  const fontsDir = path.join(SRC, 'fonts');
  const before = fs.readdirSync(fontsDir).filter((f) => /Grotesk/i.test(f));
  expect(before).toEqual([]);
});

test('the sidebar lockup is a real destination with an accessible name, never a dead control', () => {
  const rail = read('pages/Dashboard.jsx');
  // the mark is decorative; the accessible name comes from text
  expect(rail).toMatch(/spectyr_logo\.png" alt="" aria-hidden="true"/);
  expect(rail).toMatch(/SPECTR home/);
  // it keeps the app's existing home navigation (not a new behavior)
  expect(rail).toMatch(/<Link\s+to="\/"/);
  // a taller branded top area with the divider retained
  expect(rail).toMatch(/h-\[68px\][^"]*border-b border-white\/10/);
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
