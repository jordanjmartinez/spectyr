import { useState, useCallback, useEffect, useRef } from 'react';
import { apiFetch } from '../api';

// ONE incident-scope state per surface (pre-lock micro-fix M1, kept verbatim
// through Stage 5 Phase 1). The pinned header, the honesty notices, and the
// row filter all derive from this state plus the explicit fetch status --
// never from parallel derivations (the F9 defect class). `data` is the last
// successful scope read FOR THE CURRENT incident: retained through in-flight
// refreshes and failures (scoped rows are preserved and replaced atomically)
// and dropped when the incident changes, so another incident's scope can
// never filter this one.
//
// Amendment 1 Delta A (case-constant model): the per-page This-incident /
// Session-wide SELECTION is gone -- a selected case is ALWAYS case-scoped,
// no broadening control exists on the data pages, and `mode` derives from
// the case alone. The fetch machinery is unchanged M1.
export default function useIncidentScope(activeIncidentId, resetTrigger) {
  const [fetchState, setFetchState] = useState({ status: 'idle', data: null, forId: null });
  const reqSeq = useRef(0);

  const refetch = useCallback(() => {
    if (!activeIncidentId) return;
    const id = activeIncidentId;
    const seq = ++reqSeq.current;
    setFetchState(s => ({
      status: 'loading',
      data: s.forId === id ? s.data : null,
      forId: id,
    }));
    apiFetch(`/api/incidents/${id}/scope`)
      .then(res => { if (!res.ok) throw new Error('scope'); return res.json(); })
      .then(sc => {
        if (reqSeq.current !== seq) return; // superseded by a newer request
        setFetchState({
          status: 'ready',
          data: {
            hosts: new Set(sc.hosts || []),
            detectionIds: new Set(sc.detection_ids || []),
            sealed: !!sc.sealed,
          },
          forId: id,
        });
      })
      .catch(() => {
        if (reqSeq.current !== seq) return;
        setFetchState(s => ({
          status: 'error',
          data: s.forId === id ? s.data : null,
          forId: id,
        }));
      });
  }, [activeIncidentId]);

  useEffect(() => {
    if (!activeIncidentId) {
      setFetchState({ status: 'idle', data: null, forId: null });
      return;
    }
    refetch();
  }, [activeIncidentId, resetTrigger, refetch]);

  const mode = activeIncidentId ? 'incident' : 'session';
  const scopedData = fetchState.forId === activeIncidentId ? fetchState.data : null;
  return {
    mode,
    refetch,
    status: fetchState.status,
    data: mode === 'incident' ? scopedData : null,
    // Row policy, derived from the ONE state value (A1-A.3 behavior table):
    //   'all'     full session data (no case selected: the All activity state)
    //   'scoped'  filter rows by `data` (ready, or preserved through an
    //             in-flight refresh or a failure with prior data)
    //   'loading' render the loading state, zero rows
    //   'error'   render the empty error state (Retry only), zero rows
    rowPolicy: mode === 'session' ? 'all'
      : scopedData ? 'scoped'
        : fetchState.status === 'error' ? 'error' : 'loading',
  };
}
