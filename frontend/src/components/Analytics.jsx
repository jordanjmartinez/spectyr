import React, { useEffect, useState } from 'react';
import AnalystReportCard from '../components/AnalystReportCard';
import PerformanceGrade from './PerformanceGrade';
import CampaignProgress from './CampaignProgress';
import ActionHistory from './ActionHistory';

const Analytics = () => {
  const [report, setReport] = useState(null);
  const [levelData, setLevelData] = useState(null);
  const [actionHistory, setActionHistory] = useState([]);

  const fetchReportCard = () => {
    fetch("http://localhost:5000/api/analytics/report_card")
      .then((res) => res.json())
      .then((data) => setReport(data))
      .catch((err) => console.error("Failed to load report card:", err));
  };

  const fetchLevelData = () => {
    fetch("http://localhost:5000/api/current-level")
      .then((res) => res.json())
      .then((data) => setLevelData(data))
      .catch((err) => console.error("Failed to load level data:", err));
  };

  const fetchActionHistory = () => {
    fetch("http://localhost:5000/api/analytics/action_history")
      .then((res) => res.json())
      .then((data) => setActionHistory(data))
      .catch((err) => console.error("Failed to load action history:", err));
  };

  useEffect(() => {
    fetchReportCard();
    fetchLevelData();
    fetchActionHistory();
    const interval = setInterval(() => {
      fetchReportCard();
      fetchLevelData();
      fetchActionHistory();
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      {/* Campaign Progress - Full Width */}
      <CampaignProgress levelData={levelData} />

      {/* Report Card and Performance Grade */}
      <div className="grid gap-6 grid-cols-1 md:grid-cols-2">
        <AnalystReportCard report={report} />
        <PerformanceGrade report={report} />
      </div>

      {/* Action History / Mistake Review */}
      <ActionHistory history={actionHistory} />
    </div>
  );
};

export default Analytics;
