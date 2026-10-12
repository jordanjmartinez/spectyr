import React, { useEffect, useState, useCallback, useRef } from 'react';
import { apiFetch } from '../api';

/* Stage 6 playtest fix: the countdown is LOCAL. Each /api/game-state poll
   only re-syncs a deadline ref; a 250ms tick drives the display and fires
   onTimeout the moment the deadline passes, so the failure overlay appears
   at 0:00 even if a poll is throttled, dropped, or late. The server's
   timer_expired flag remains the authoritative backup trigger (and the
   backend now auto-pauses an expired run on its own). */
const GameTimer = ({ onTimeout, disabled }) => {
  const [gameState, setGameState] = useState(null);
  const [timeRemaining, setTimeRemaining] = useState(null);
  const deadlineRef = useRef(null); // Date.now()-based ms deadline; null = no live countdown
  const hasTriggeredTimeoutRef = useRef(false);

  // Props live in refs so the poll/tick intervals mount ONCE instead of
  // being torn down on every parent render (the old effect churn left
  // windows where a missed poll was the only expiry trigger).
  const onTimeoutRef = useRef(onTimeout);
  onTimeoutRef.current = onTimeout;
  const disabledRef = useRef(disabled);
  disabledRef.current = disabled;

  const fireTimeout = useCallback(() => {
    if (hasTriggeredTimeoutRef.current || disabledRef.current) return;
    hasTriggeredTimeoutRef.current = true;
    onTimeoutRef.current?.();
  }, []);

  // Responses can land out of order: a slow poll issued against a dead run
  // may resolve after the retried run already started. Only the most
  // recently issued request may update state or trigger expiry, otherwise
  // a stale expired read could fire the overlay over a fresh run.
  const reqSeqRef = useRef(0);

  const fetchGameState = useCallback(async () => {
    const seq = ++reqSeqRef.current;
    try {
      const res = await apiFetch('/api/game-state');
      const data = await res.json();
      if (seq !== reqSeqRef.current) return; // stale out-of-order response
      setGameState(data);

      if (data.game_mode === 'hardcore' && data.timer_remaining !== null) {
        setTimeRemaining(Math.ceil(data.timer_remaining));
        // A paused session's clock is frozen server-side; pin the display
        // and stop the local countdown instead of drifting past it.
        deadlineRef.current = data.paused
          ? null
          : Date.now() + data.timer_remaining * 1000;
      } else {
        deadlineRef.current = null;
        setTimeRemaining(null);
      }

      if (data.timer_expired && data.game_mode === 'hardcore') {
        fireTimeout();
      } else if (!data.timer_expired) {
        // Re-arm only once the server reports a non-expired state (a reset
        // or a fresh run), never while the dead run is still being read.
        hasTriggeredTimeoutRef.current = false;
      }
    } catch (err) {
      console.error('Failed to fetch game state', err);
    }
  }, [fireTimeout]);

  useEffect(() => {
    fetchGameState();
    const poll = setInterval(fetchGameState, 1000);
    const tick = setInterval(() => {
      if (deadlineRef.current === null) return;
      const remainingMs = deadlineRef.current - Date.now();
      setTimeRemaining(Math.max(0, Math.ceil(remainingMs / 1000)));
      if (remainingMs <= 0) {
        deadlineRef.current = null; // one local shot; the server flag backs it up
        fireTimeout();
      }
    }, 250);
    return () => {
      clearInterval(poll);
      clearInterval(tick);
    };
  }, [fetchGameState, fireTimeout]);

  // Don't show anything in training mode or if no timer
  if (!gameState || gameState.game_mode !== 'hardcore' || timeRemaining === null) {
    return null;
  }

  const minutes = Math.floor(timeRemaining / 60);
  const seconds = timeRemaining % 60;
  const isLow = timeRemaining <= 30;
  const isCritical = timeRemaining <= 10;

  return (
    <div
      className={`flex items-center justify-center gap-2 px-2 lg:px-3 py-2 rounded-md border ${
        isCritical
          ? 'bg-[#4a1f1f] border-[#7a3a3a] animate-pulse'
          : isLow
          ? 'bg-[#4a3f22] border-[#7a6f3a]'
          : 'bg-white/5 border-white/10'
      }`}
    >
      <img
        src="/hacker_icon.jpeg"
        alt="Hardcore"
        className={`w-7 h-7 shrink-0 object-contain ${isCritical ? 'animate-pulse' : ''}`}
      />
      <span
        className={`log-mono text-base lg:text-lg tracking-widest ${
          isCritical ? 'text-[#e0a0a0]' : isLow ? 'text-[#e0c48a]' : 'text-gray-200'
        }`}
      >
        {minutes}:{seconds.toString().padStart(2, '0')}
      </span>
    </div>
  );
};

export default GameTimer;
