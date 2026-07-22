"""Deterministic simulation epoch (Stage 4 Phase 1, contract R8 / tier A1).

One wall-clock-free timeline per session. The epoch is a stable digest of the
session id mapped into a fixed canonical work week: SIM_BASE (a Monday 08:00
UTC) plus 0..EPOCH_WINDOW_MINUTES-1 minutes, the same stable-key practice the
world snapshot and detection ids already use. `start_simulator` freezes the
epoch into `world["started_at"]`, so endpoint world times, the response-action
clock, event occurrence times, and TIMEFRAME resolution share one timeline.

Occurrence times (contract Section 9, scaffold Section 6):
- authored events: `authored_base(session_id, queue_position)` plus the
  scenario's authored per-step offsets; `[lo, hi]` gap ranges resolve from the
  dedicated per-session `gap_rng` stream, never the shared global RNG.
- background events: epoch + BACKGROUND_SPACING_S * event_seq (stamped at the
  pool-append choke point; Phase 1.2).

Bare harness sessions (no session id) fall back to SIM_BASE and the global
`random` module, so parity_check_v2's seeded bare-session renders are
untouched. Drip orchestration (next_drip_at, injected_at, chain_complete_at,
timer_start) stays wall clock by design: those are visibility times, not
occurrence times.
"""
import hashlib
import random
from datetime import datetime, timedelta, timezone

# A fixed canonical Monday morning; every session's timeline lives inside the
# Mon 08:00 .. Fri 07:59 window that follows it.
SIM_BASE = datetime(2026, 3, 16, 8, 0, 0, tzinfo=timezone.utc)
EPOCH_WINDOW_MINUTES = 4 * 24 * 60          # Mon 08:00 through Fri 07:59

# Authored incidents anchor at epoch + (queue_position - 1) * this spacing.
POSITION_SPACING_S = 120

# Background occurrence time advances this many sim-seconds per event_seq step
# (scaffold Section 6: 3s chosen under the quantified coherence bound; the
# first permitted tuning knob if the bound fails again).
BACKGROUND_SPACING_S = 3


def _digest(*parts):
    return hashlib.sha256(":".join(str(p) for p in parts).encode()).digest()


def epoch_dt(session_id):
    """The session's simulation epoch as an aware UTC datetime (whole
    minutes). Deterministic given the session id; SIM_BASE when there is no
    session identity (bare harness sessions)."""
    if not session_id:
        return SIM_BASE
    minutes = (int.from_bytes(_digest(session_id, "sim_epoch")[:8], "big")
               % EPOCH_WINDOW_MINUTES)
    return SIM_BASE + timedelta(minutes=minutes)


def epoch_iso(session_id):
    return epoch_dt(session_id).isoformat()


def authored_base(session_id, queue_position):
    """Occurrence-time base for the incident at 1-based queue_position."""
    pos = queue_position or 1
    return epoch_dt(session_id) + timedelta(seconds=POSITION_SPACING_S * (pos - 1))


def background_occurrence(started_at_iso, seq):
    """Occurrence timestamp for the background event with this event_seq,
    derived from the frozen session epoch (world['started_at'])."""
    base = datetime.fromisoformat(started_at_iso)
    return (base + timedelta(seconds=BACKGROUND_SPACING_S * seq)).isoformat()


def gap_rng(session_id):
    """The dedicated per-session RNG stream that resolves authored [lo, hi]
    gap ranges. Seeded from the epoch digest, so gap sequences are a pure
    function of session identity and queue composition, independent of the
    shared global RNG."""
    return random.Random(int.from_bytes(_digest(session_id, "gaps")[:8], "big"))
