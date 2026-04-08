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
      className={`self-start flex items-center gap-2 px-2 py-1 rounded-lg border-2 ${
        isCritical
          ? 'bg-red-500/30 border-red-500 animate-pulse'
          : isLow
          ? 'bg-yellow-500/20 border-yellow-500'
          : 'bg-gray-800/80 border-gray-600'
      }`}
    >
      <img src="/hacker_icon.jpeg" alt="" className="w-8 h-8 sm:w-11 sm:h-11" />
      <span
        className={`text-lg sm:text-xl tracking-widest ${
          isCritical ? 'text-red-400' : isLow ? 'text-yellow-400' : 'text-white'
        }`}
        style={{ fontFamily: "'JetBrains Mono', sans-serif" }}
      >
        {minutes}:{seconds.toString().padStart(2, '0')}
      </span>
    </div>
  );
};

export default GameTimer;
