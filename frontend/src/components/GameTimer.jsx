import React, { useEffect, useState, useCallback } from 'react';

const GameTimer = ({ onTimeout }) => {
  const [gameState, setGameState] = useState(null);
  const [timeRemaining, setTimeRemaining] = useState(null);

  const fetchGameState = useCallback(async () => {
    try {
      const res = await fetch('http://localhost:5000/api/game-state');
      const data = await res.json();
      setGameState(data);

      if (data.timer_remaining !== null) {
        setTimeRemaining(Math.ceil(data.timer_remaining));
      } else {
        setTimeRemaining(null);
      }

      // Check for timeout
      if (data.timer_expired && data.game_mode === 'hardcore') {
        onTimeout?.();
      }
    } catch (err) {
      console.error('Failed to fetch game state', err);
    }
  }, [onTimeout]);

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
      className={`flex items-center gap-3 px-3 py-2 rounded-xl border-2 ${
        isCritical
          ? 'bg-red-500/30 border-red-500 animate-pulse'
          : isLow
          ? 'bg-yellow-500/20 border-yellow-500'
          : 'bg-gray-800/80 border-gray-600'
      }`}
    >
      <img src="/hacker_fav.png" alt="" className="w-14 h-14" />
      <span
        className={`text-3xl tracking-widest ${
          isCritical ? 'text-red-400' : isLow ? 'text-yellow-400' : 'text-white'
        }`}
        style={{ fontFamily: "'Share Tech Mono', monospace" }}
      >
        {minutes}:{seconds.toString().padStart(2, '0')}
      </span>
    </div>
  );
};

export default GameTimer;
