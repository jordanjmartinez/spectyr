# Deployment Notes

## SPA routing on the static host (Stage 6 playtest fix)

The frontend is a single-page app (react-router with `BrowserRouter`), deployed
as a **Render static site** behind Cloudflare (`spectyr.dev`). Client-side
routes such as `/sim` and `/docs` exist only inside the JS bundle, so a direct
load or a reload of those URLs asks the static host for a file that does not
exist. Without a fallback, Render answers with its plain `404 Not Found` --
the playtest defect: deep links to `spectyr.dev/sim` failed, and reloading
`/sim` after a reset failed the same way.

### The permanent fix: a rewrite rule (one-time dashboard action)

**Status: APPLIED by the owner 2026-10-12 and verified live** (`GET /sim`
returns 200 with the app shell; it previously returned Render's plain 404).
The shim below is now the dormant safety net.

In the Render dashboard for the static site, under **Redirects/Rewrites**, add:

| Source | Destination | Action |
|--------|-------------|--------|
| `/*`   | `/index.html` | Rewrite |

With that rule every unknown path serves the app shell with a `200`, the
router takes over, and the in-repo fallback below never activates. If the
service is ever converted to a Blueprint, the equivalent `render.yaml` entry
is:

```yaml
routes:
  - type: rewrite
    source: /*
    destination: /index.html
```

### The in-repo fallback (works without dashboard access)

Render static sites automatically serve `404.html` from the publish directory
for unmatched paths. The repo ships a shim pair:

- `frontend/public/404.html` stores the requested path
  (`sessionStorage["spectyr_deep_link"]`) and bounces to `/`.
- `frontend/src/spaFallback.js` (`restoreDeepLink()`, called in `index.js`
  before React mounts) restores that path into history, so the router lands
  on the intended route. Restores are same-origin paths only; full or
  protocol-relative URLs are refused.

This makes deep links work on any static host with custom-404 support, at the
cost of one visible bounce and a `404` status on the first response. The
rewrite rule above is strictly better; the shim is the safety net.

The SPA itself also carries a catch-all route (`*` -> `/`) so genuinely
unknown in-app paths land on the home page instead of an empty shell.

## Single-worker backend

Unchanged standing rule: the Flask backend must run as a single worker
(`gunicorn.conf.py` pins `workers = 1`); sessions and log-writer threads are
in-process.
