import React, { useEffect, useState } from 'react';
import API_BASE_URL from '../config';

const StatCards = () => {
  const [stats, setStats] = useState({
    total_alerts: 0,
    critical_alerts: 0,
    high_severity_rate: 0.0,
  });

  useEffect(() => {
    const fetchStats = () => {
      fetch(`${API_BASE_URL}/api/analytics`)
        .then(res => res.json())
        .then(data => setStats(data))
        .catch(err => console.error('Error fetching stats:', err));
    };

    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="bg-[#161b22] rounded-xl p-8 flex flex-col sm:flex-row justify-between items-center text-white">
      <div className="flex-1 text-center border-b sm:border-b-0 sm:border-r border-gray-700 px-6 py-4">
        <p className="text-base text-gray-400 mb-1">Total Alerts</p>
        <p className="text-4xl font-bold">{stats.total_alerts}</p>
      </div>

      <div className={`flex-1 text-center border-b sm:border-b-0 sm:border-r border-gray-700 px-6 py-4 ${stats.critical_alerts > 0 ? 'text-red-500' : 'text-white'}`}>
        <p className="text-base text-gray-400 mb-1">Critical Alerts</p>
        <p className="text-4xl font-bold">{stats.critical_alerts}</p>
      </div>

      <div className="flex-1 text-center px-6 py-4">
        <p className="text-base text-gray-400 mb-1">High Severity Rate</p>
        <p className="text-4xl font-bold">{stats.high_severity_rate}%</p>
      </div>
    </div>
  );
};

export default StatCards;
