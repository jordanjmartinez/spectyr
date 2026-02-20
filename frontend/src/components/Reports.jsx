import React, { useEffect, useState } from 'react';
import { apiFetch } from '../api';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';
import IncidentReportForm from '../components/IncidentReportForm';

const STATUS_OPTIONS = ['Open', 'In Progress', 'Resolved', 'Closed'];
const SEVERITY_OPTIONS = ['Critical', 'High', 'Medium', 'Low'];

const Reports = ({ setReportCount, reportCount, analystName }) => {
  const [reports, setReports] = useState([]);
  const [expandedIndex, setExpandedIndex] = useState(null);
  const [editReport, setEditReport] = useState(null);
  const [showNewReport, setShowNewReport] = useState(false);
  const [statusDropdownId, setStatusDropdownId] = useState(null);
  const [severityDropdownId, setSeverityDropdownId] = useState(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState(null);
  const [activeTab, setActiveTab] = useState('open');


  const fetchReports = async () => {
    try {
      const res = await apiFetch('/api/reports');
      const data = await res.json();
      setReports(data.reverse());
    } catch (err) {
      console.error("Failed to fetch reports", err);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  useEffect(() => {
    if (setReportCount) {
      setReportCount(reports.length);
    }
  }, [reports, setReportCount]);

  const toggleRow = (index) => {
    setExpandedIndex(expandedIndex === index ? null : index);
  };

  const handleStatusChange = async (report, newStatus) => {
    try {
      const updated = { ...report, status: newStatus };
      const res = await apiFetch(`/api/reports/${report.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updated),
      });
      if (res.ok) {
        setReports(prev => prev.map(r => r.id === report.id ? updated : r));
      } else {
        console.error("Failed to update status");
      }
    } catch (err) {
      console.error("Error updating status", err);
    } finally {
      setStatusDropdownId(null);
    }
  };

  const handleSeverityChange = async (report, newSeverity) => {
    try {
      const updated = { ...report, severity: newSeverity };
      const res = await apiFetch(`/api/reports/${report.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updated),
      });
      if (res.ok) {
        setReports(prev => prev.map(r => r.id === report.id ? updated : r));
      } else {
        console.error("Failed to update severity");
      }
    } catch (err) {
      console.error("Error updating severity", err);
    } finally {
      setSeverityDropdownId(null);
    }
  };

  const handleDeleteReport = async (reportId) => {
    try {
      const res = await apiFetch(`/api/reports/${reportId}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        setReports(prev => prev.filter(r => r.id !== reportId));
      } else {
        console.error("Failed to delete report");
      }
    } catch (err) {
      console.error("Error deleting report", err);
    } finally {
      setDeleteConfirmId(null);
    }
  };

  const handleExportPDF = async (report) => {
    const element = document.createElement('div');
    element.style.cssText = 'width: 700px; padding: 40px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #fff; color: #1a1a1a;';

    const formatDate = (timestamp) => {
      const date = new Date(timestamp);
      return date.toLocaleDateString('en-GB') + ' at ' + date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
    };

    element.innerHTML = `
      <div style="border-bottom: 2px solid #e5e5e5; padding-bottom: 20px; margin-bottom: 24px;">
        <h1 style="margin: 0 0 8px 0; font-size: 24px; font-weight: 600; color: #111;">${report.title || 'Untitled Report'}</h1>
        <p style="margin: 0; font-size: 13px; color: #666;">Generated ${formatDate(new Date())}</p>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr 1fr 1fr 1fr; gap: 16px; margin-bottom: 24px; padding: 16px; background: #f8f9fa; border-radius: 8px;">
        <div>
          <p style="margin: 0 0 4px 0; font-size: 11px; text-transform: uppercase; color: #666; letter-spacing: 0.5px;">Severity</p>
          <p style="margin: 0; font-size: 14px; font-weight: 500; color: ${
            report.severity === 'Critical' ? '#b91c1c' :
            report.severity === 'High' ? '#ea580c' :
            report.severity === 'Medium' ? '#ca8a04' : '#047857'
          };">${report.severity || '—'}</p>
        </div>
        <div>
          <p style="margin: 0 0 4px 0; font-size: 11px; text-transform: uppercase; color: #666; letter-spacing: 0.5px;">Status</p>
          <p style="margin: 0; font-size: 14px; font-weight: 500;">${report.status || 'Open'}</p>
        </div>
        <div>
          <p style="margin: 0 0 4px 0; font-size: 11px; text-transform: uppercase; color: #666; letter-spacing: 0.5px;">Owner</p>
          <p style="margin: 0; font-size: 14px; ${report.owner === 'Unassigned' || !report.owner ? 'font-style: italic; color: #999;' : ''}">${report.owner || 'Unassigned'}</p>
        </div>
        <div>
          <p style="margin: 0 0 4px 0; font-size: 11px; text-transform: uppercase; color: #666; letter-spacing: 0.5px;">MITRE Tactic</p>
          <p style="margin: 0; font-size: 14px;">${report.mitre_tactic || '—'}</p>
        </div>
        <div>
          <p style="margin: 0 0 4px 0; font-size: 11px; text-transform: uppercase; color: #666; letter-spacing: 0.5px;">Kill Chain</p>
          <p style="margin: 0; font-size: 14px;">${report.kill_chain || '—'}</p>
        </div>
      </div>

      <div style="margin-bottom: 20px;">
        <p style="margin: 0 0 8px 0; font-size: 12px; text-transform: uppercase; color: #666; letter-spacing: 0.5px; font-weight: 500;">What was observed?</p>
        <p style="margin: 0; font-size: 14px; line-height: 1.6; color: #333;">${report.description || '—'}</p>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 20px;">
        <div>
          <p style="margin: 0 0 8px 0; font-size: 12px; text-transform: uppercase; color: #666; letter-spacing: 0.5px; font-weight: 500;">Affected Systems</p>
          <p style="margin: 0; font-size: 13px; font-family: monospace; color: #333;">${report.affected_hosts || '—'}</p>
        </div>
        <div>
          <p style="margin: 0 0 8px 0; font-size: 12px; text-transform: uppercase; color: #666; letter-spacing: 0.5px; font-weight: 500;">Recommended Actions</p>
          <p style="margin: 0; font-size: 14px; line-height: 1.6; color: #333;">${report.mitigation || '—'}</p>
        </div>
      </div>

      <div style="border-top: 1px solid #e5e5e5; padding-top: 16px; margin-top: 24px;">
        <p style="margin: 0; font-size: 12px; color: #888;">Report created: ${formatDate(report.timestamp)}</p>
      </div>
    `;

    document.body.appendChild(element);

    const canvas = await html2canvas(element, { scale: 2 });
    const imgData = canvas.toDataURL('image/png');
    const pdf = new jsPDF('p', 'mm', 'a4');
    const imgWidth = 190;
    const imgHeight = (canvas.height * imgWidth) / canvas.width;
    pdf.addImage(imgData, 'PNG', 10, 10, imgWidth, imgHeight);
    pdf.save(`incident-${report.title || 'report'}.pdf`);

    document.body.removeChild(element);
  };

  // Filter reports based on active tab
  const filteredReports = activeTab === 'open'
    ? reports.filter(r => r.status !== 'Closed')
    : reports.filter(r => r.status === 'Closed');

  // Header component used in both states
  const Header = () => (
    <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center mb-6 space-y-4 sm:space-y-0">
      <h2 className="text-2xl font-semibold text-white">
        Incident Reports <span className="text-gray-500 font-normal">({filteredReports.length})</span>
      </h2>
      <div className="flex flex-wrap items-center gap-3">
        <button
          onClick={() => setShowNewReport(true)}
          className="inline-flex items-center justify-center px-4 py-2 text-sm font-medium rounded-md border transition bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600 focus:outline-none focus:ring-2 focus:ring-gray-500"
        >
          Create Report
        </button>
        <div className="flex space-x-2">
          <button
            onClick={() => setActiveTab('open')}
            className={`px-4 py-2 text-sm font-medium rounded-md border transition ${
              activeTab === 'open'
                ? 'bg-[#21262d] text-white border-gray-600'
                : 'bg-transparent text-gray-400 border-gray-700 hover:bg-[#21262d]'
            }`}
          >
            Open
          </button>
          <button
            onClick={() => setActiveTab('closed')}
            className={`px-4 py-2 text-sm font-medium rounded-md border transition ${
              activeTab === 'closed'
                ? 'bg-[#21262d] text-white border-gray-600'
                : 'bg-transparent text-gray-400 border-gray-700 hover:bg-[#21262d]'
            }`}
          >
            Closed
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <>
      <Header />


      {filteredReports.length === 0 ? (
        <div className="bg-[#161b22] p-6 rounded-xl">
          <div className="flex flex-col items-center justify-center py-8 min-h-[320px]">
            <img src="/ghost-reports.png" alt="Ghost" className="w-28 h-28 sm:w-40 sm:h-40 opacity-90 mb-3" />
            <p className="font-mono text-sm text-gray-400">&gt; Complete a triage to document incidents here.</p>
          </div>
        </div>
      ) : (
      <div className="space-y-4">
        {filteredReports.map((report, index) => (
          <div
            key={report.id}
            className="bg-[#161b22] border border-gray-700 p-4 rounded-xl shadow transition-all duration-300 ease-in-out"
          >
            {/* Card Header - Clickable to expand */}
            <div
              className="flex flex-col sm:flex-row sm:justify-between sm:items-start cursor-pointer"
              onClick={() => toggleRow(index)}
            >
              {/* Left column on desktop: title + metadata */}
              <div className="sm:flex-1 sm:min-w-0">
                <h3 className="text-base sm:text-xl font-bold text-white sm:truncate sm:pr-4">
                  {report.title || 'Untitled Report'}
                </h3>
                {/* Desktop metadata — below title */}
                <div className="hidden sm:flex items-center gap-3 mt-1 whitespace-nowrap">
                  <span className="text-white text-sm">
                    {new Date(report.timestamp).toLocaleDateString('en-GB')} at {new Date(report.timestamp).toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit' })}
                  </span>
                  <span className="text-gray-600">|</span>
                  <span className="text-white text-sm">Assigned to:</span>
                  <span className="text-white text-sm">{(report.owner && report.owner !== 'Unassigned') ? report.owner : (analystName || 'Unknown')}</span>
                </div>
              </div>

              {/* Badges, Actions and chevron */}
              <div className="flex items-center gap-1 sm:gap-2 mt-2 sm:mt-0 sm:ml-4 sm:flex-shrink-0">
                {/* Severity badge */}
                <div className="relative">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setSeverityDropdownId(severityDropdownId === report.id ? null : report.id);
                    }}
                    className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-semibold rounded-md border transition cursor-pointer hover:bg-gray-700 uppercase tracking-wider bg-gray-800/80 text-gray-200 border-gray-700"
                  >
                    {report.severity || 'Unset'}
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </button>
                  {severityDropdownId === report.id && (
                    <>
                      <div
                        className="fixed inset-0 z-10"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSeverityDropdownId(null);
                        }}
                      />
                      <div className="absolute right-0 top-full mt-1 z-20 bg-[#21262d] border border-gray-600 rounded-md shadow-lg py-1 flex flex-col min-w-[100px]">
                        {SEVERITY_OPTIONS.map((severity) => (
                          <button
                            key={severity}
                            onClick={(e) => {
                              e.stopPropagation();
                              handleSeverityChange(report, severity);
                            }}
                            className={`text-left px-3 py-1.5 text-sm hover:bg-gray-700 transition whitespace-nowrap ${
                              report.severity === severity ? 'text-white bg-gray-700' : 'text-gray-300'
                            }`}
                          >
                            {severity}
                          </button>
                        ))}
                      </div>
                    </>
                  )}
                </div>

                {/* Status badge */}
                <div className="relative">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setStatusDropdownId(statusDropdownId === report.id ? null : report.id);
                    }}
                    className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-semibold rounded-md border transition cursor-pointer hover:bg-gray-700 uppercase tracking-wider bg-gray-800/80 text-gray-200 border-gray-700"
                  >
                    {report.status || 'Open'}
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </button>
                  {statusDropdownId === report.id && (
                    <>
                      <div
                        className="fixed inset-0 z-10"
                        onClick={(e) => {
                          e.stopPropagation();
                          setStatusDropdownId(null);
                        }}
                      />
                      <div className="absolute right-0 top-full mt-1 z-20 bg-[#21262d] border border-gray-600 rounded-md shadow-lg py-1 flex flex-col min-w-[100px]">
                        {STATUS_OPTIONS.map((status) => (
                          <button
                            key={status}
                            onClick={(e) => {
                              e.stopPropagation();
                              handleStatusChange(report, status);
                            }}
                            className={`text-left px-3 py-1.5 text-sm hover:bg-gray-700 transition whitespace-nowrap ${
                              report.status === status ? 'text-white bg-gray-700' : 'text-gray-300'
                            }`}
                          >
                            {status}
                          </button>
                        ))}
                      </div>
                    </>
                  )}
                </div>

                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setEditReport(report);
                  }}
                  title="Edit"
                  className="p-1.5 sm:p-2 rounded text-gray-400 hover:text-white hover:bg-gray-700 transition"
                >
                  <svg className="w-4 h-4 sm:w-5 sm:h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                  </svg>
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    handleExportPDF(report);
                  }}
                  title="Export PDF"
                  className="p-1.5 sm:p-2 rounded text-gray-400 hover:text-white hover:bg-gray-700 transition"
                >
                  <svg className="w-4 h-4 sm:w-5 sm:h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setDeleteConfirmId(report.id);
                  }}
                  title="Delete"
                  className="p-1.5 sm:p-2 rounded text-gray-400 hover:text-white hover:bg-gray-700 transition"
                >
                  <svg className="w-4 h-4 sm:w-5 sm:h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
                <svg
                  className={`w-5 h-5 text-gray-500 hover:text-white transition-transform duration-300 ease-in-out ${
                    expandedIndex === index ? 'rotate-180' : 'rotate-0'
                  }`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </div>

              {/* Mobile metadata — after badges */}
              <div className="flex sm:hidden items-center gap-3 mt-1 whitespace-nowrap">
                <span className="text-white text-sm">
                  {new Date(report.timestamp).toLocaleDateString('en-GB')} at {new Date(report.timestamp).toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit' })}
                </span>
                <span className="text-gray-600">|</span>
                <span className="text-white text-sm">Assigned to:</span>
                <span className="text-white text-sm">{(report.owner && report.owner !== 'Unassigned') ? report.owner : (analystName || 'Unknown')}</span>
              </div>
            </div>

            {/* Expandable Content */}
            <div
              className={`grid transition-all duration-300 ease-in-out ${
                expandedIndex === index ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
              }`}
            >
              <div className="overflow-hidden min-h-0">
                <div className="mt-4 border-t border-gray-700 pt-4" style={{ fontFamily: "'Open Sans', sans-serif" }}>
                  {/* 4-column metadata row */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                    <div>
                      <span className="text-sm text-gray-400 font-medium">Severity</span>
                      <p className="text-gray-300 mt-1 text-sm">{report.severity || '—'}</p>
                    </div>
                    <div>
                      <span className="text-sm text-gray-400 font-medium">Status</span>
                      <p className="text-gray-300 mt-1 text-sm">{report.status || 'Open'}</p>
                    </div>
                    <div>
                      <span className="text-sm text-gray-400 font-medium">MITRE Tactic</span>
                      <p className="text-gray-300 mt-1 text-sm">{report.mitre_tactic || '—'}</p>
                    </div>
                    <div>
                      <span className="text-sm text-gray-400 font-medium">Kill Chain</span>
                      <p className="text-gray-300 mt-1 text-sm">{report.kill_chain || '—'}</p>
                    </div>
                  </div>

                  {/* Description */}
                  <div className="mb-4">
                    <span className="text-sm text-gray-400 font-medium">What was observed?</span>
                    <p className="text-gray-300 mt-2 leading-relaxed text-sm">{report.description || '—'}</p>
                  </div>

                  {/* Affected Systems */}
                  <div className="mb-4">
                    <span className="text-sm text-gray-400 font-medium">Affected Systems</span>
                    <p className="text-gray-300 mt-2 text-sm font-mono">{report.affected_hosts || '—'}</p>
                  </div>

                  {/* Recommended Actions */}
                  <div>
                    <span className="text-sm text-gray-400 font-medium">Recommended Actions</span>
                    <p className="text-gray-300 mt-2 leading-relaxed text-sm">{report.mitigation || '—'}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirmId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black/70"
            onClick={() => setDeleteConfirmId(null)}
          />
          <div className="relative bg-[#161b22] border border-gray-700 rounded-xl p-6 w-full max-w-md mx-4 shadow-2xl">
            <h3 className="text-lg font-semibold text-white text-center mb-4">Delete Report</h3>
            <p className="text-gray-400 mb-6 text-center">
              Are you sure you want to delete this report? This action cannot be undone.
            </p>
            <div className="flex justify-center gap-3">
              <button
                onClick={() => setDeleteConfirmId(null)}
                className="px-4 py-2 text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-300 border border-gray-600 transition"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDeleteReport(deleteConfirmId)}
                className="px-4 py-2 text-sm font-medium rounded-md bg-[#21262d] hover:bg-[#30363d] text-gray-300 border border-gray-600 transition"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Report Modal */}
      {editReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black/70"
            onClick={() => setEditReport(null)}
          />
          <div className="relative bg-[#161b22] border border-gray-700 rounded-xl p-6 w-full max-w-2xl mx-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            <IncidentReportForm
              initialData={editReport}
              onSubmit={async (updated) => {
                try {
                  const res = await apiFetch(`/api/reports/${updated.id}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(updated),
                  });
                  if (res.ok) {
                    await fetchReports();
                  }
                } catch (err) {
                  console.error("Error during report update", err);
                } finally {
                  setEditReport(null);
                }
              }}
              onCancel={() => setEditReport(null)}
              inline
            />
          </div>
        </div>
      )}

      {/* Create Report Modal */}
      {showNewReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black/70"
            onClick={() => setShowNewReport(false)}
          />
          <div className="relative bg-[#161b22] border border-gray-700 rounded-xl p-6 w-full max-w-2xl mx-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            <IncidentReportForm
              initialData={{}}
              onSubmit={async (formData) => {
                try {
                  const res = await apiFetch('/api/reports', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(formData),
                  });
                  if (res.ok) {
                    await fetchReports();
                  }
                } catch (err) {
                  console.error("Error creating report", err);
                } finally {
                  setShowNewReport(false);
                }
              }}
              onCancel={() => setShowNewReport(false)}
              inline
            />
          </div>
        </div>
      )}
    </>
  );
};

export default Reports;
