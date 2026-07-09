import React, { useEffect, useState, useCallback, useRef } from 'react';
import { apiFetch } from '../api';

const GameTimer = ({ onTimeout, disabled }) => {
  const [gameState, setGameState] = useState(null);
  const [timeRemaining, setTimeRemaining] = useState(null);
  const hasTriggeredTimeoutRef = useRef(false);

  const fetchGameState = useCallback(async () => {
    try {
      const res = await apiFetch('/api/game-state');
      const data = await res.json();
      setGameState(data);

      if (data.timer_remaining !== null) {
        setTimeRemaining(Math.ceil(data.timer_remaining));
      } else {
        setTimeRemaining(null);
      }

      // Check for timeout — gate with ref to prevent firing multiple times
      if (data.timer_expired && data.game_mode === 'hardcore' && !disabled) {
        if (!hasTriggeredTimeoutRef.current) {
          hasTriggeredTimeoutRef.current = true;
          onTimeout?.();
        }
      } else if (!data.timer_expired) {
        hasTriggeredTimeoutRef.current = false; // reset after game reset
      }
    } catch (err) {
      console.error('Failed to fetch game state', err);
    }
  }, [onTimeout, disabled]);

  useEffect(() => {
    fetchGameState();
    const interval = setInterval(fetchGameState, 1000);
    return () => clearInterval(interval);
  }, [fetchGameState]);

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
      <svg
        className={`w-4 h-4 shrink-0 ${isCritical ? 'text-[#e0a0a0]' : isLow ? 'text-[#e0c48a]' : 'text-gray-400'}`}
        fill="none" stroke="currentColor" viewBox="0 0 24 24"
      >
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
      <span
        className={`text-base lg:text-lg tracking-widest ${
          isCritical ? 'text-[#e0a0a0]' : isLow ? 'text-[#e0c48a]' : 'text-gray-200'
        }`}
        style={{ fontFamily: "'JetBrains Mono', sans-serif" }}
      >
        {minutes}:{seconds.toString().padStart(2, '0')}
      </span>
    </div>
  );
};

export default GameTimer;
