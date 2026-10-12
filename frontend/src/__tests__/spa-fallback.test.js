/**
 * Stage 6 playtest fix: /sim deep links and reloads resolve.
 *
 * Static hosting serves client-side routes a 404; the shim pair
 * (public/404.html -> src/spaFallback.js) bounces the request through the
 * app shell and restores the intended path before the router mounts.
 * Pinned here:
 * - restoreDeepLink restores a stored path into history exactly once;
 * - only same-origin plain paths restore (never full or protocol-relative
 *   URLs, never non-path garbage);
 * - no-op when nothing is stored, when the path already matches, and when
 *   storage is unavailable;
 * - the shim, the bootstrap call, and the router catch-all stay wired
 *   (file-level guards, same style as brand-lockup).
 */
import fs from 'fs';
import path from 'path';
import { restoreDeepLink, DEEP_LINK_KEY } from '../spaFallback';

const SRC = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(SRC, rel), 'utf8');

const makeStorage = (initial = {}) => {
  const map = new Map(Object.entries(initial));
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    removeItem: (k) => map.delete(k),
    setItem: (k, v) => map.set(k, String(v)),
    has: (k) => map.has(k),
  };
};
const makeHistory = () => {
  const calls = [];
  return { replaceState: (...a) => calls.push(a), calls };
};
const LOC = { pathname: '/', search: '', hash: '' };

test('a stored deep link restores into history once and clears the key', () => {
  const storage = makeStorage({ [DEEP_LINK_KEY]: '/sim' });
  const hist = makeHistory();
  expect(restoreDeepLink(storage, hist, LOC)).toBe(true);
  expect(hist.calls).toEqual([[null, '', '/sim']]);
  expect(storage.has(DEEP_LINK_KEY)).toBe(false);
  // a second boot finds nothing to restore
  expect(restoreDeepLink(storage, hist, LOC)).toBe(false);
  expect(hist.calls).toHaveLength(1);
});

test('only same-origin plain paths restore', () => {
  for (const bad of ['https://evil.example/x', '//evil.example/x', 'sim', '', 'javascript:alert(1)']) {
    const storage = makeStorage({ [DEEP_LINK_KEY]: bad });
    const hist = makeHistory();
    expect(restoreDeepLink(storage, hist, LOC)).toBe(false);
    expect(hist.calls).toHaveLength(0);
    expect(storage.has(DEEP_LINK_KEY)).toBe(false); // still consumed
  }
});

test('no-op when nothing stored, when the path already matches, or when storage throws', () => {
  const hist = makeHistory();
  expect(restoreDeepLink(makeStorage(), hist, LOC)).toBe(false);
  expect(restoreDeepLink(
    makeStorage({ [DEEP_LINK_KEY]: '/sim' }), hist,
    { pathname: '/sim', search: '', hash: '' })).toBe(false);
  const broken = { getItem: () => { throw new Error('denied'); }, removeItem: () => {} };
  expect(restoreDeepLink(broken, hist, LOC)).toBe(false);
  expect(hist.calls).toHaveLength(0);
});

test('the shim, the bootstrap call, and the router catch-all stay wired', () => {
  const shim = fs.readFileSync(path.join(SRC, '..', 'public', '404.html'), 'utf8');
  expect(shim).toContain(DEEP_LINK_KEY);
  expect(shim).toContain("location.replace('/')");
  expect(read('index.js')).toMatch(/restoreDeepLink\(\)/);
  const app = read('App.jsx');
  expect(app).toMatch(/path="\*"/);
  expect(app).toMatch(/Navigate to="\/" replace/);
});
