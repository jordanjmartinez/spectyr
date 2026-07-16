# UI Design Notes (in-repo record)

The Stage 1 endpoints UI spec and its addendum live outside this repository.
This file records design-language decisions made after that spec, so the
in-repo source of truth stays complete. Additions land here with the stage
that introduced them.

## Dark table headers (Stage 1.5)

The standard for ALL data tables app-wide: SIEM results, endpoint tabs,
alerts, reports, and future detections/threats lists.

- Header row uses the navbar palette family: `#101218` background,
  `#d1d5db` text, no bottom border, top corners rounded 0.5rem.
- Body rows stay light per the existing page treatment.
- Implementation: add `className="dark-thead"` to the `<thead>`; the class
  lives in `src/index.css`. Do not hand-roll per-table header colors.
- Sort affordances inside a dark header hover to white.

Applied in Stage 1.5 to: SiemTable, Endpoints list, every EndpointDetail
tab table, GroupedAlerts (scenario tracking, notable events, embedded event
logs), Reports, ActionHistory.

## SIEM view conventions (Stage 1.5)

- Card view is the default; table view is the compact alternative. Both are
  views over the same cached, client-filtered pool.
- Cards carry the severity left edge (same hues as table row edges) and a
  source-family dot using the muted categorical set in `siemUtils.js`.
- The expandable raw-log JSON renders `sanitizeEvent` output only: the
  whitelist of fields a real SIEM would store. Simulation-internal fields
  (scenario wiring, answers, analyst state) must never render there.
- Time presets anchor to the pool's latest timestamp (scenario clock),
  never wall time.
