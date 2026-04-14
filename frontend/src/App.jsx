import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { apiFetch } from './api';

import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import Analytics from './components/Analytics';

const LOADING_MESSAGES = [
  "Initializing SPECTYR...",
  "Scanning threat feeds...",
  "Calibrating detection engines...",
  "Deploying honeypots...",
  "Bribing the firewall...",
  "Convincing the intern to stop clicking links...",
  "Almost there...",
];

function App() {
  const [backendReady, setBackendReady] = useState(false);
  const [messageIndex, setMessageIndex] = useState(0);

  useEffect(() => {
    if (backendReady) return;
    const interval = setInterval(() => {
      setMessageIndex(prev => {
        if (prev >= LOADING_MESSAGES.length - 1) {
          clearInterval(interval);
          return prev;
        }
        return prev + 1;
      });
    }, 7000);
    return () => clearInterval(interval);
  }, [backendReady]);

  useEffect(() => {
    let cancelled = false;

    const checkHealth = async () => {
      try {
        const res = await apiFetch('/api/health');
        if (res.ok && !cancelled) {
          setBackendReady(true);
        }
      } catch {
        // Backend not up yet, will retry
      }
    };

    checkHealth();

    const interval = setInterval(() => {
      if (!cancelled) checkHealth();
    }, 3000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  if (!backendReady) {
    return (
      <div className="min-h-screen bg-[#0d1117] flex flex-col items-center justify-center text-white">
        <img src="/spectyr_logo.png" alt="SPECTYR Logo" className="h-32 w-32 mb-6 animate-pulse" />
        <h1 className="text-4xl tracking-wider mb-4" style={{ fontFamily: "'Aldrich', sans-serif" }}>
          SPECTYR
        </h1>
        <p className="text-gray-400 text-lg mb-8">{LOADING_MESSAGES[messageIndex]}</p>
        {/* Progress bar */}
        <div className="w-64 sm:w-80 h-1.5 bg-gray-800 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-[2000ms] ease-out"
            style={{
              width: backendReady ? '100%' : `${((messageIndex + 1) / LOADING_MESSAGES.length) * 85}%`,
              background: '#9ca3af',
              boxShadow: `0 0 ${8 + messageIndex * 2}px rgba(156, 163, 175, ${0.3 + messageIndex * 0.08})`,
            }}
          />
        </div>
      </div>
    );
  }

  return (
    <Router>
      <Navbar />

      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/analytics" element={<Analytics />} />
      </Routes>

      <footer className="bg-[#0d1117] px-4 sm:px-6 py-4 flex flex-col min-[674px]:flex-row items-center min-[674px]:justify-between gap-2">
        <div className="flex items-center gap-2">
          <img src="/spectyr_logo.png" alt="Spectyr" className="h-8 w-8 object-contain" />
          <span className="text-base tracking-wider text-white" style={{ fontFamily: "'Aldrich', sans-serif" }}>SPECTYR</span>
          <span className="text-sm text-gray-500 hidden sm:inline">|</span>
          <span className="text-sm text-white hidden sm:inline">SOC Simulation Training</span>
        </div>
        <span className="text-sm text-white">&copy; 2026 Spectyr. All rights reserved.</span>
      </footer>
    </Router>
  );
}

export default App;
