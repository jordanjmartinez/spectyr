import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { apiFetch } from './api';

import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import Analytics from './components/Analytics';

function App() {
  const [backendReady, setBackendReady] = useState(false);

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
        <p className="text-gray-400 text-lg mb-6">Initializing SPECTYR...</p>
        <div className="flex gap-1.5">
          <div className="w-2 h-2 bg-gray-500 rounded-full animate-bounce [animation-delay:0ms]" />
          <div className="w-2 h-2 bg-gray-500 rounded-full animate-bounce [animation-delay:150ms]" />
          <div className="w-2 h-2 bg-gray-500 rounded-full animate-bounce [animation-delay:300ms]" />
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
    </Router>
  );
}

export default App;
