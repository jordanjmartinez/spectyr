// Stage 6 playtest fix (SPA deep links): public/404.html stores the path a
// static host could not serve (a direct /sim load or a reload), then bounces
// to the app shell. This restores it into history BEFORE React mounts so the
// router sees the intended route. No-op unless the 404 shim ran.
export const DEEP_LINK_KEY = 'spectyr_deep_link';

export function restoreDeepLink(
  storage = window.sessionStorage,
  hist = window.history,
  loc = window.location
) {
  let saved = null;
  try {
    saved = storage.getItem(DEEP_LINK_KEY);
    if (saved !== null) storage.removeItem(DEEP_LINK_KEY);
  } catch (e) {
    return false; // storage unavailable (privacy mode): nothing to restore
  }
  // Only same-origin path restores: the stored value must be a plain
  // absolute path, never a full or protocol-relative URL that could send
  // the history entry off-origin.
  if (!saved || !saved.startsWith('/') || saved.startsWith('//')) return false;
  const current = loc.pathname + loc.search + loc.hash;
  if (saved === current) return false;
  hist.replaceState(null, '', saved);
  return true;
}
