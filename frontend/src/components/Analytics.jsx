import React, { useEffect, useState } from 'react';
import { apiFetch } from '../api';
import AnalystReportCard from '../components/AnalystReportCard';
import { GradeCard, MttrCard } from './PerformanceGrade';
import CampaignProgress from './CampaignProgress';
import ActionHistory from './ActionHistory';
import ScoreSections from './ScoreSections';
import LearningReview from './LearningReview';
import { SESSION_PERFORMANCE_LABEL } from './uiCopy';
import { CARD_STYLE, PageIntro } from './ui';

const Analytics = ({ onReset, analystName, setAnalyticsCount, isVisible = true,
                     reviewRequest = null, activeIncident = null }) => {
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

  // Stage 3.9A submission gate: report_card serves a discriminated shape. Until
  // an incident is submitted it is {state: in_progress, progress}, carrying
  // observable activity only, no grades. Grading (and every field the cards
  // read) exists ONLY under report.grading, once at least one incident is
  // submitted. Flatten that grading into the shape the cards expect, or null.
  const submitted = report?.state === 'submitted';
  const grading = submitted ? report.grading : null;
  const cardReport = grading ? {
    ...grading,
    grade: grading.composite?.grade || '-',
    threats_caught: grading.classification?.threats_caught ?? 0,
    wrong_category: grading.classification?.wrong_category ?? 0,
    fp_identified: grading.classification?.fp_identified ?? 0,
    fp_missed: grading.classification?.fp_missed ?? 0,
  } : (report?.error ? report : null);
  const progress = report?.state === 'in_progress' ? report.progress : null;

  return (
    <div className="space-y-6">
      {/* VA1: functional subtitle + the ONE incident pill (relevant when
          an investigation is active); Reset stays in the controls slot. */}
      <PageIntro
        incident={activeIncident}
        right={(
          <button
            onClick={onReset}
            className="px-3 py-1.5 text-xs font-medium rounded-md border transition bg-white hover:bg-[#eef1f4] text-[#1a2332] border-[#d0d7de]"
          >
            Reset Simulation
          </button>
        )}
      />

      {/* Campaign Progress - Full Width */}
      <CampaignProgress levelData={levelData} report={cardReport} analystName={analystName} />

      {/* Stage 5 commit 5.4 (ratified B-OD-1 Option 1): the Metrics tab is
          the per-incident Learning Review home -- the one durable teaching
          venue. Rendered above the session aggregate; the two blocks keep
          the 3.9B labeling split (Incident Grade vs Session Performance). */}
      <LearningReview reviewRequest={reviewRequest} isVisible={isVisible} />

      {/* The session aggregate ("Session Performance", 3.9B labeling; was
          "Report Card") sits outside the container like the other section
          headings; the container keeps stats + grade */}
      <div>
        <h2 className="t-section mb-4">{SESSION_PERFORMANCE_LABEL}</h2>
        {progress ? (
          <div className="rounded-xl p-4 sm:p-6" style={CARD_STYLE}>
            <p className="text-sm text-[#57606a]">
              Grading appears once you submit an incident. Investigate the queue, triage detections, take response actions, then submit each incident to lock in your call and see how it scored.
            </p>
            <div className="mt-4 flex flex-wrap gap-x-6 gap-y-2 text-sm text-[#57606a]">
              <span><span className="font-medium text-[#1a2332]">{progress.submitted ?? 0}</span> submitted</span>
              <span><span className="font-medium text-[#1a2332]">{progress.detections_triaged ?? 0}</span> detections triaged</span>
              <span><span className="font-medium text-[#1a2332]">{progress.actions_executed ?? 0}</span> actions taken</span>
            </div>
          </div>
        ) : (
          <div className="rounded-xl" style={CARD_STYLE}>
            <div className="grid grid-cols-1 md:grid-cols-2">
              <div className="p-4 sm:p-6 border-b md:border-b-0 md:border-r border-[#e2e6ea]">
                <AnalystReportCard report={cardReport} />
              </div>
              <div className="p-4 sm:p-6">
                {/* Recharts holders render only while the tab is visible: a
                    hidden (display:none) chart measures 0 and floods the
                    console, starving layout for the charts that are visible. */}
                {isVisible && <GradeCard report={cardReport} />}
              </div>
            </div>
          </div>
        )}
      </div>
      {isVisible && !progress && <MttrCard report={cardReport} />}

      {/* Stage 3d composite ruling: the composite is the headline (GradeCard);
          Classification, Detections, and Response render as independent scored
          sections beneath it. Submission-gated: only shown once graded. */}
      {!progress && <ScoreSections isVisible={isVisible} report={cardReport} />}

      {/* Action History / Mistake Review (populated post-submission only) */}
      <ActionHistory history={actionHistory} />
    </div>
  );
};

export default Analytics;
