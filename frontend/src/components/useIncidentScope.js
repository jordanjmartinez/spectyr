import { useState, useCallback, useEffect, useRef } from 'react';
import { apiFetch } from '../api';

// Pre-lock micro-fix M1 (Stage 5A contract Section 11.1, ratified OD-16):
// ONE incident-scope state per surface. The scope label, the control's
// selected state (visual + aria-pressed), and the row filter all derive from
// `selection` plus the explicit fetch `status` -- never from parallel
// derivations (the F9 defect: the toggle highlight read one value while the
// label and the filter read another). `data` is the last successful scope
// read FOR THE CURRENT incident: it is retained through in-flight refreshes
// and failures (scoped rows are preserved and replaced atomically) and is
// dropped when the incident changes, so another incident's scope can never
// filter this one. Broadening to Session-wide happens only through the
// explicit control, never as a fallback.
export default function useIncidentScope(activeIncidentId, resetTrigger) {
  const [selection, setSelection] = useState('incident');
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

  const mode = activeIncidentId && selection === 'incident' ? 'incident' : 'session';
  const scopedData = fetchState.forId === activeIncidentId ? fetchState.data : null;
  return {
    mode,
    selection,
    setSelection,
    refetch,
    status: fetchState.status,
    data: mode === 'incident' ? scopedData : null,
    // Row policy, derived from the ONE state value (contract 11.1 table):
    //   'all'     unfiltered rows (Session-wide selected)
    //   'scoped'  filter rows by `data` (ready, or preserved through an
    //             in-flight refresh or a failure with prior data)
    //   'loading' render the loading state, zero rows
    //   'error'   render the empty error state, zero rows
    rowPolicy: mode === 'session' ? 'all'
      : scopedData ? 'scoped'
        : fetchState.status === 'error' ? 'error' : 'loading',
  };
}
