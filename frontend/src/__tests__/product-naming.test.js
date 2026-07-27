/**
 * VE (final visual-polish pass): the product's user-visible name is
 * Spectr, presented without a descriptive subtitle; ONE shared Start
 * control is the only product-entry CTA; the Docs describe the current
 * product. Internal identifiers deliberately keep their historical
 * lowercase spelling (asset filenames, the session storage key, the
 * video path) and authored scenario content keeps its fictional vendor
 * prefix (see brand-lockup.test.js) -- this battery guards the VISIBLE
 * naming only, so it scans product source with comments stripped and
 * only rejects the capital-S brand forms.
 */
import fs from 'fs';
import path from 'path';

const SRC = path.join(__dirname, '..');
const PUB = path.join(SRC, '..', 'public');
const read = (p) => fs.readFileSync(p, 'utf8');
const stripComments = (text) => text
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/^\s*\/\/.*$/gm, '');

const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
  const p = path.join(dir, e.name);
  if (e.isDirectory()) return ['__tests__', 'fonts'].includes(e.name) ? [] : walk(p);
  return /\.(js|jsx)$/.test(e.name) ? [p] : [];
});

test('the old brand form never renders: no capital-S Spectyr in product source', () => {
  for (const p of walk(SRC)) {
    const rel = path.relative(SRC, p).replace(/\\/g, '/');
    const code = stripComments(read(p));
    // internal identifiers stay lowercase (spectyr_logo.png,
    // spectyr_session_id, spectyrvideo.mp4); the brand forms are gone
    expect([rel, /Spectyr|SPECTYR/.test(code)]).toEqual([rel, false]);
  }
});

test('the browser title and install metadata name the product Spectr, with no subtitle', () => {
  const html = read(path.join(PUB, 'index.html'));
  expect(html).toMatch(/<title>Spectr<\/title>/);
  expect(html).not.toMatch(/Spectyr|SOC Simulation Training/);
  const manifest = JSON.parse(read(path.join(PUB, 'manifest.json')));
  expect(manifest.name).toBe('Spectr');
  expect(manifest.short_name).toBe('Spectr');
});

test('ONE shared Start control: the retired labels are gone and every entry surface renders it', () => {
  for (const p of walk(SRC)) {
    const rel = path.relative(SRC, p).replace(/\\/g, '/');
    const code = stripComments(read(p));
    expect([rel, /Start Sim|Start Simulation|Launch Sim/.test(code)]).toEqual([rel, false]);
  }
  // the four entry surfaces all render the shared component
  for (const f of ['pages/Landing.jsx', 'pages/Docs.jsx', 'pages/Dashboard.jsx',
                   'components/Navbar.jsx']) {
    expect([f, /<StartButton/.test(read(path.join(SRC, f)))]).toEqual([f, true]);
  }
  // the pill geometry is defined once and shared (VE5: the rail Reset
  // consumes the same exported class list)
  const sb = read(path.join(SRC, 'components', 'StartButton.jsx'));
  expect(sb).toMatch(/export const CTA_PILL/);
  expect(read(path.join(SRC, 'pages', 'Dashboard.jsx'))).toMatch(/CTA_PILL/);
});

test('the Docs describe the current product: eight sections, no retired-model vocabulary', () => {
  const docs = stripComments(read(path.join(SRC, 'pages', 'Docs.jsx')));
  for (const id of ['getting-started', 'how-spectr-works', 'guided-and-hardcore',
                    'detections', 'siem', 'endpoints', 'response', 'learning-review']) {
    expect([id, docs.includes(`id: '${id}'`)]).toEqual([id, true]);
  }
  // the retired model never returns: no queue workflow, no Analytics
  // destination, no arrival-cadence or concurrency mechanics, no
  // pre-submit reveal (Check Answer is also source-guarded elsewhere)
  expect(docs).not.toMatch(/queue/i);
  expect(docs).not.toMatch(/Analytics/);
  expect(docs).not.toMatch(/20 to 40|20-40 seconds|three open|simultaneously/i);
  expect(docs).not.toMatch(/check.?answer/i);
  // the landing links target real rewritten sections
  const landing = stripComments(read(path.join(SRC, 'pages', 'Landing.jsx')));
  const anchors = [...landing.matchAll(/\/docs#([a-z-]+)/g)].map((m) => m[1]);
  expect(anchors.length).toBeGreaterThan(0);
  for (const a of anchors) {
    expect([a, docs.includes(`id: '${a}'`)]).toEqual([a, true]);
  }
});
