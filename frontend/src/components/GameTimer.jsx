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
      className={`self-start flex items-center gap-2 px-2 py-1 rounded-lg border ${
        isCritical
          ? 'bg-[#3a1f1f] border-[#7a3a3a] animate-pulse'
          : isLow
          ? 'bg-[#3a3522] border-[#7a6f3a]'
          : 'bg-[#161b22] border-gray-700'
      }`}
    >
      <img src="/hacker_icon.jpeg" alt="" className="w-8 h-8 sm:w-11 sm:h-11" />
      <span
        className={`text-lg sm:text-xl tracking-widest ${
          isCritical ? 'text-[#b26666]' : isLow ? 'text-[#c28e46]' : 'text-gray-200'
        }`}
        style={{ fontFamily: "'JetBrains Mono', sans-serif" }}
      >
        {minutes}:{seconds.toString().padStart(2, '0')}
      </span>
    </div>
  );
};

export default GameTimer;
