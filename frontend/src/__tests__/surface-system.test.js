/**
 * VP16 (owner correction): the content-surface system. Dark surfaces are
 * reserved for primary navigation, selected segmented controls, primary
 * buttons, and deliberate high-emphasis states. Every DATA surface --
 * tables across Dashboard, Incidents, SIEM, Detections, Endpoints,
 * Response, Metrics -- uses the ONE shared light header; no ordinary
 * card carries a decorative dark top stripe.
 */
import fs from 'fs';
import path from 'path';

const SRC = path.join(__dirname, '..');
const css = fs.readFileSync(path.join(SRC, 'index.css'), 'utf8');
const read = (rel) => fs.readFileSync(path.join(SRC, rel), 'utf8');
const sources = () => {
  const out = [];
  for (const dir of ['components', 'pages']) {
    for (const f of fs.readdirSync(path.join(SRC, dir))) {
      if (/\.(js|jsx)$/.test(f)) out.push([`${dir}/${f}`, read(`${dir}/${f}`)]);
    }
  }
  return out;
};

test('one shared LIGHT table header primitive, with the ruled values', () => {
  const block = css.match(/\.data-thead th,\s*\.dark-thead th\s*{[^}]*}/)[0];
  // soft neutral-gray background + dark high-contrast text (not a black banner)
  expect(block).toMatch(/background:\s*#f6f8fa/);
  expect(block).toMatch(/color:\s*#1a2332/);
  const size = parseFloat(block.match(/font-size:\s*([\d.]+)px/)[1]);
  expect(size).toBeGreaterThanOrEqual(12);
  expect(size).toBeLessThanOrEqual(13);
  expect(block).toMatch(/font-weight:\s*600/);
  const tracking = parseFloat(block.match(/letter-spacing:\s*([\d.]+)em/)[1]);
  expect(tracking).toBeLessThanOrEqual(0.02);
  expect(block).toMatch(/border-bottom:\s*1px solid #e2e6ea/);
  expect(block).toMatch(/border-top:\s*none/);
  // the dense variant is a stronger GRAY, never a dark banner
  expect(css).toMatch(/\.data-thead--dense th[\s\S]*?background:\s*#eef1f4/);
});

test('no data surface renders a dark table header any more', () => {
  // the retired class is an ALIAS of the light system (so a stale usage
  // cannot resurrect the black banner) and no source references it
  expect(css).not.toMatch(/\.dark-thead th\s*{\s*background:\s*#101218/);
  for (const [name, src] of sources()) {
    expect([name, /dark-thead/.test(src)]).toEqual([name, false]);
  }
});

test('every primary workspace table uses the shared light header', () => {
  const tabled = {
    'components/IncidentDashboard.jsx': 'Dashboard recent results',
    'components/SiemTable.jsx': 'SIEM table view',
    'components/Detections.jsx': 'Detections queue',
    'components/Endpoints.jsx': 'Endpoints list',
    'components/EndpointDetail.jsx': 'Endpoint tabs',
    'components/Response.jsx': 'Response groups + log',
    'components/ActionHistory.jsx': 'Metrics attempt history',
  };
  for (const [file, what] of Object.entries(tabled)) {
    const src = read(file);
    const heads = (src.match(/<thead/g) || []).length;
    const light = (src.match(/data-thead/g) || []).length;
    expect([what, heads > 0, light >= heads]).toEqual([what, true, true]);
  }
});

test('no ordinary content card carries a decorative dark top stripe', () => {
  for (const [name, src] of sources()) {
    // the retired stripe: a 2px bar filled with the accent->ink gradient
    const stripe = /h-0\.5[^>]*linear-gradient\(to right, #16436b, #101218\)/.test(src);
    expect([name, stripe]).toEqual([name, false]);
  }
  // the shared Card primitive cannot render one even if asked
  const ui = read('components/ui.jsx');
  const card = ui.match(/export const Card = [\s\S]*?\n\);/)[0];
  expect(card).not.toMatch(/HAIRLINE/);
});

test('the app header is the light inline cell of the unified shell row (VC1: the black capsule is retired)', () => {
  const hdr = read('components/AppHeader.jsx');
  // the HEADER BAR's own classes (the dropdown panel below it is a
  // separate surface and legitimately carries an elevation shadow)
  const bar = hdr.match(/<header\s+className="([^"]+)"/)[1];
  expect(bar).not.toMatch(/bg-\[#101218\]/);        // no rounded black container
  expect(bar).not.toMatch(/rounded/);               // a row cell, not a capsule
  expect(bar).toMatch(/h-\[72px\]/);                // shares the brand-cell height
  expect(bar).toMatch(/border-b border-\[#e2e6ea\]/); // divider only, no border box
  expect(bar).not.toMatch(/border border-/);        // no leftover dark border box
  expect(bar).not.toMatch(/shadow/);                // no heavy shadow
  expect(bar).not.toMatch(/drop-shadow|blur-/);     // no glow
  // the title keeps the shared token with its own light-surface ink
  expect(hdr).toMatch(/<h1 className="t-page">/);
});
