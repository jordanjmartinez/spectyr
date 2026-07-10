import React, { useEffect, useState } from 'react';
import { apiFetch } from '../api';
import AnalystReportCard from '../components/AnalystReportCard';
import { GradeCard, MttrCard } from './PerformanceGrade';
import CampaignProgress from './CampaignProgress';
import ActionHistory from './ActionHistory';

const Analytics = ({ onReset, analystName, setAnalyticsCount }) => {
  const [report, setReport] = useState(null);
  const [levelData, setLevelData] = useState(null);
  const [actionHistory, setActionHistory] = useState([]);

  const fetchReportCard = () => {
    apiFetch('/api/analytics/report_card')
      .then((res) => res.json())
      .then((data) => setReport(data))
      .catch((err) => console.error("Failed to load report card:", err));
  };

  const fetchLevelData = () => {
    apiFetch('/api/current-level')
      .then((res) => res.json())
      .then((data) => setLevelData(data))
      .catch((err) => console.error("Failed to load level data:", err));
  };

  const fetchActionHistory = () => {
    apiFetch('/api/analytics/action_history')
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

  useEffect(() => {
    if (setAnalyticsCount) {
      setAnalyticsCount(actionHistory.length);
    }
  }, [actionHistory, setAnalyticsCount]);

  return (
    <div className="space-y-6">
      {/* Campaign Progress - Full Width */}
      <CampaignProgress levelData={levelData} report={report} onReset={onReset} analystName={analystName} />

      {/* "Report Card" heading sits outside the container (like the other
          section headings); the container keeps stats + grade, Grade heading removed */}
      <div>
        <h2 className="text-xl sm:text-2xl font-semibold text-[#1a2332] mb-4">Report Card</h2>
        <div className="rounded-2xl" style={{ background: '#ffffff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}>
          <div className="grid grid-cols-1 md:grid-cols-2">
            <div className="p-4 sm:p-6 border-b md:border-b-0 md:border-r border-[#e2e6ea]">
              <AnalystReportCard report={report} />
            </div>
            <div className="p-4 sm:p-6">
              <GradeCard report={report} />
            </div>
          </div>
        </div>
      </div>
      <MttrCard report={report} />

      {/* Action History / Mistake Review */}
      <ActionHistory history={actionHistory} />
    </div>
  );
};

export default Analytics;
