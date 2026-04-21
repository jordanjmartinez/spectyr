import React, { useEffect, useState } from 'react';
import { apiFetch } from '../api';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';
import IncidentReportForm from '../components/IncidentReportForm';
import SeverityPill from '../components/SeverityPill';

const STATUS_OPTIONS = ['Open', 'Closed'];
const SEVERITY_OPTIONS = ['Low', 'Medium', 'High', 'Critical'];

const getReportNumber = (id) => {
  const hash = id.replace(/-/g, '').slice(0, 8);
  return 1000 + (parseInt(hash, 16) % 24001);
};

const Reports = ({ setReportCount, reportCount, analystName, resetTrigger }) => {
  const [reports, setReports] = useState([]);
  const [expandedIndex, setExpandedIndex] = useState(null);
  const [editReport, setEditReport] = useState(null);

  const [statusDropdownId, setStatusDropdownId] = useState(null);
  const [dropdownPos, setDropdownPos] = useState({ top: 0, left: 0 });
  const [severityDropdownId, setSeverityDropdownId] = useState(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterOpen, setFilterOpen] = useState(true);
  const [filterClosed, setFilterClosed] = useState(false);
  const [showFilterDropdown, setShowFilterDropdown] = useState(false);
  const [, setTick] = useState(0);
  const [fadingOutId, setFadingOutId] = useState(null);


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
  }, [resetTrigger]);

  useEffect(() => {
    const interval = setInterval(fetchReports, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (setReportCount) {
      setReportCount(reports.length);
    }
  }, [reports, setReportCount]);

  useEffect(() => {
    const interval = setInterval(() => setTick(t => t + 1), 60000);
    return () => clearInterval(interval);
  }, []);

  const getRelativeTime = (timestamp) => {
    const diffMs = Date.now() - new Date(timestamp);
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);
    if (diffMins < 1) return 'just now';
    if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
    if (diffDays < 7) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
    return new Date(timestamp).toLocaleDateString('en-GB');
  };

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
        // Check if the row would be filtered out after status change
        const wouldHide = (newStatus === 'Closed' && !filterClosed) || (newStatus === 'Open' && !filterOpen);
        setReports(prev => prev.map(r => r.id === report.id ? updated : r));
        if (wouldHide) {
          setFadingOutId(report.id);
          setTimeout(() => setFadingOutId(null), 1200);
        }
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
          <p style="margin: 0 0 4px 0; font-size: 11px; text-transform: uppercase; color: #666; letter-spacing: 0.5px;">Case ID</p>
          <p style="margin: 0; font-size: 14px;">${report.alert_id || 'INC-' + getReportNumber(report.id)}</p>
        </div>
        <div>
          <p style="margin: 0 0 4px 0; font-size: 11px; text-transform: uppercase; color: #666; letter-spacing: 0.5px;">MITRE ATT&CK</p>
          <p style="margin: 0; font-size: 14px;">${report.mitre_tactic || '—'}</p>
        </div>
        <div>
          <p style="margin: 0 0 4px 0; font-size: 11px; text-transform: uppercase; color: #666; letter-spacing: 0.5px;">Kill Chain Phase</p>
          <p style="margin: 0; font-size: 14px;">${report.kill_chain || '—'}</p>
        </div>
      </div>

      <div style="margin-bottom: 20px;">
        <p style="margin: 0 0 8px 0; font-size: 12px; text-transform: uppercase; color: #666; letter-spacing: 0.5px; font-weight: 500;">Description</p>
        <p style="margin: 0; font-size: 14px; line-height: 1.6; color: #333;">${report.description || '—'}</p>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 20px;">
        <div>
          <p style="margin: 0 0 8px 0; font-size: 12px; text-transform: uppercase; color: #666; letter-spacing: 0.5px; font-weight: 500;">Affected Systems</p>
          <p style="margin: 0; font-size: 13px; font-family: monospace; color: #333;">${report.affected_hosts || '—'}</p>
        </div>
        <div>
          <p style="margin: 0 0 8px 0; font-size: 12px; text-transform: uppercase; color: #666; letter-spacing: 0.5px; font-weight: 500;">Mitigation Steps</p>
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

  // Filter reports based on status filters and search
  const filteredReports = reports.filter(r => {
    // Keep fading-out rows visible
    if (fadingOutId === r.id) return true;
    // Status filter
    const isOpen = r.status !== 'Closed';
    const isClosed = r.status === 'Closed';
    if (filterOpen && !filterClosed && !isOpen) return false;
    if (filterClosed && !filterOpen && !isClosed) return false;
    if (!filterOpen && !filterClosed) return false;

    // Search filter
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    const reportNumber = r.alert_id || `INC-${getReportNumber(r.id)}`;
    return (
      (r.title || '').toLowerCase().includes(term) ||
      reportNumber.toLowerCase().includes(term) ||
      (r.severity || '').toLowerCase().includes(term) ||
      (r.status || '').toLowerCase().includes(term) ||
      (r.description || '').toLowerCase().includes(term) ||
      (r.mitre_tactic || '').toLowerCase().includes(term) ||
      (r.kill_chain || '').toLowerCase().includes(term)
    );
  });

  // Header section
  const header = (
    <div className="flex flex-col gap-3 mb-6">
      <div className="flex flex-row items-center justify-between gap-2 sm:gap-3">
        <h2 className="text-xl sm:text-2xl font-semibold text-white whitespace-nowrap">
          Reports <span className={`font-normal ml-1 ${filteredReports.length > 0 ? "text-gray-500" : "invisible"}`}>{filteredReports.length || "0"}</span>
        </h2>
        <div className="flex items-center gap-2 sm:gap-3">
          <div className="relative">
            <button
              onClick={() => setShowFilterDropdown(!showFilterDropdown)}
              className="inline-flex items-center justify-center gap-1 px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md border transition bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600 focus:outline-none focus:ring-2 focus:ring-gray-500"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
              </svg>
              Filter
            </button>
            {showFilterDropdown && (
              <>
                <div
                  className="fixed inset-0 z-10"
                  onClick={() => setShowFilterDropdown(false)}
                />
                <div className="absolute right-0 top-full mt-1 z-20 bg-[#161b22] border border-gray-700 rounded py-1 flex flex-col min-w-[100px] sm:min-w-[120px]">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setFilterOpen(!filterOpen);
                    }}
                    className="flex items-center gap-2 text-left px-2.5 sm:px-3 py-1 sm:py-1.5 text-xs sm:text-sm hover:bg-gray-700 transition text-gray-400"
                  >
                    <span className={`w-3 h-3 sm:w-3.5 sm:h-3.5 rounded border ${filterOpen ? 'bg-gray-300 border-gray-300' : 'border-gray-600'}`} />
                    Open
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setFilterClosed(!filterClosed);
                    }}
                    className="flex items-center gap-2 text-left px-2.5 sm:px-3 py-1 sm:py-1.5 text-xs sm:text-sm hover:bg-gray-700 transition text-gray-400"
                  >
                    <span className={`w-3 h-3 sm:w-3.5 sm:h-3.5 rounded border ${filterClosed ? 'bg-gray-300 border-gray-300' : 'border-gray-600'}`} />
                    Closed
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
        <div className="relative">
          <input
            type="text"
            placeholder="Search reports..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            maxLength={300}
            className="w-full pl-4 pr-10 py-2 rounded-md bg-[#0d1117] border border-gray-700 text-white text-sm placeholder-gray-400 focus:border-[#5882b4] focus:outline-none transition-colors"
          />
          {!searchTerm && (
            <svg className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          )}
          {searchTerm && (
            <button
              onClick={() => setSearchTerm('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>
    </div>
  );

  return (
    <>
      {header}


      {filteredReports.length === 0 && !searchTerm ? (
        <div
          className="p-6 rounded-xl flex-1 flex flex-col"
          style={{
            background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(88,130,180,0.3), transparent) border-box',
            border: '1px solid transparent',
            boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)',
          }}
        >
          <div className="flex flex-col items-center justify-center py-8 flex-1">
            <img src="/ghost-reports.png" alt="Ghost" className="w-28 h-28 sm:w-40 sm:h-40 opacity-90 mb-3" />
            <p className="font-mono text-xs sm:text-sm text-gray-400 text-center sm:text-left">&gt;<span className="animate-blink">|</span> Write a report from Alerts to document your findings.</p>
          </div>
        </div>
      ) : filteredReports.length === 0 && searchTerm ? (
        <div className="flex flex-col items-center justify-center py-12">
          <svg
            className="w-12 h-12 sm:w-16 sm:h-16 text-gray-500 mb-3"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
          </svg>
          <p className="font-mono text-xs sm:text-sm text-gray-400 text-center sm:text-left">&gt;<span className="animate-blink">|</span> No matching reports for "{searchTerm}"</p>
        </div>
      ) : (
      <div
        className="p-3 sm:p-6 rounded-xl"
        style={{
          background: 'linear-gradient(#161b22, #161b22) padding-box, linear-gradient(to bottom, rgba(88,130,180,0.3), transparent) border-box',
          border: '1px solid transparent',
          boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05)',
        }}
      >
        <div className="overflow-x-auto overflow-y-hidden mobile-scroll-wrapper">
          <table className="w-full min-w-[600px] log-text text-left text-gray-300 border-separate border-spacing-0">
            <thead>
              <tr className="text-xs sm:text-sm uppercase text-gray-400 tracking-wider">
                <th className="w-10 px-2 sm:px-4 py-3 font-medium border-b border-gray-600"></th>
                <th className="px-2 sm:px-4 py-3 font-medium whitespace-nowrap border-b border-gray-600">Title</th>
                <th className="w-[110px] sm:w-[140px] px-2 sm:px-4 py-3 font-medium whitespace-nowrap text-center border-b border-gray-600">Severity</th>
                <th className="w-[100px] sm:w-[130px] px-2 sm:px-4 py-3 font-medium whitespace-nowrap text-center border-b border-gray-600">Status</th>
                <th className="w-[110px] sm:w-[190px] px-2 sm:px-4 py-3 font-medium whitespace-nowrap text-center border-b border-gray-600">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {filteredReports.map((report, index) => (
                <React.Fragment key={report.id}>
                  <tr
                    className={`hover:bg-white/5 cursor-pointer border-b border-gray-700/50 transition-all duration-700 ${fadingOutId === report.id ? 'opacity-0' : 'opacity-100'}`}
                    onClick={() => toggleRow(index)}
                  >
                    <td className="px-2 sm:px-4 py-4">
                      <svg
                        className={`w-5 h-5 text-gray-500 hover:text-white transition-transform duration-300 ease-in-out ${
                          expandedIndex === index ? 'rotate-180' : 'rotate-0'
                        }`}
                        fill="none" stroke="currentColor" viewBox="0 0 24 24"
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    </td>
                    <td className="px-2 sm:px-4 py-4">
                      <p className="text-sm sm:text-base font-medium text-gray-200 whitespace-nowrap">{report.title || 'Untitled Report'}</p>
                      <p className="text-xs sm:text-sm text-gray-400 mt-0.5"><span className="text-[#5882b4] font-medium">{report.alert_id || `INC-${getReportNumber(report.id)}`}</span> · {getRelativeTime(report.timestamp)}</p>
                    </td>
                    <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center">
                      <SeverityPill level={report.severity} />
                    </td>
                    <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={(e) => { e.stopPropagation(); handleStatusChange(report, (report.status || 'Open') === 'Open' ? 'Closed' : 'Open'); }}
                        className="inline-flex items-center cursor-pointer group"
                      >
                        <span className="text-gray-300 group-hover:text-white transition-colors">{report.status || 'Open'}</span>
                      </button>
                    </td>
                    <td className="px-2 sm:px-4 py-4 whitespace-nowrap text-center" onClick={(e) => e.stopPropagation()}>
                      <div className="inline-flex items-center gap-2">
                        <button
                          onClick={(e) => { e.stopPropagation(); setEditReport(report); }}
                          className="inline-flex items-center justify-center px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600 focus:outline-none focus:ring-2 focus:ring-gray-500"
                        >
                          Edit
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); setDeleteConfirmId(report.id); }}
                          className="inline-flex items-center justify-center px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600 focus:outline-none focus:ring-2 focus:ring-gray-500"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                  <tr>
                    <td colSpan="5" className="p-0">
                      <div className={`grid transition-all duration-300 ease-in-out ${
                        expandedIndex === index ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
                      }`}>
                        <div className="overflow-hidden min-h-0">
                          <div style={{ height: '1px', background: 'linear-gradient(to right, rgba(88,130,180,0.3), transparent)' }} />
                          <div className="px-6 py-4">
                            <div className="mb-4">
                              <span className="text-sm sm:text-base text-white font-medium">Title</span>
                              <p className="text-gray-300 mt-1 text-sm sm:text-base break-words">{report.title || '—'}</p>
                            </div>
                            <div className="mb-4">
                              <span className="text-sm sm:text-base text-white font-medium">Description</span>
                              <p className="text-gray-300 mt-2 leading-relaxed text-sm sm:text-base break-words">{report.description || '—'}</p>
                            </div>
                            <div className="mb-4">
                              <span className="text-sm sm:text-base text-white font-medium">Affected Systems</span>
                              <p className="text-gray-300 mt-2 text-sm sm:text-base break-words">{report.affected_hosts || '—'}</p>
                            </div>
                            <div className="mb-4">
                              <span className="text-sm sm:text-base text-white font-medium">Mitigation Steps</span>
                              <p className="text-gray-300 mt-2 leading-relaxed text-sm sm:text-base break-words">{report.mitigation || '—'}</p>
                            </div>
                            <div>
                              <span className="text-sm sm:text-base text-white font-medium">MITRE ATT&CK</span>
                              <p className="text-gray-300 mt-1 text-sm sm:text-base">{report.mitre_tactic || '—'}</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirmId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black/70"
            onClick={() => setDeleteConfirmId(null)}
          />
          <div className="relative bg-[#161b22] border border-gray-700 rounded-xl p-6 w-full max-w-md mx-4 shadow-2xl animate-modalIn">
            <button
              type="button"
              onClick={() => setDeleteConfirmId(null)}
              aria-label="Close"
              className="absolute top-3 right-3 p-1 text-gray-400 hover:text-white transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
            <h3 className="text-lg font-semibold text-white mb-4">Delete Report</h3>
            <div className="mb-5" style={{ height: '1px', background: 'linear-gradient(to right, rgba(88,130,180,0.3), transparent)' }} />
            <p className="text-gray-400 mb-6">
              Are you sure you want to delete this report? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setDeleteConfirmId(null)}
                className="inline-flex items-center justify-center px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600 focus:outline-none focus:ring-2 focus:ring-gray-500"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDeleteReport(deleteConfirmId)}
                className="inline-flex items-center justify-center px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-[#5882b4] hover:bg-[#7aa4d4] text-white border-[#5882b4] hover:border-[#7aa4d4] focus:outline-none focus:ring-2 focus:ring-[#5882b4]"
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
          <div className="relative bg-[#161b22] border border-gray-700 rounded-xl p-3 sm:p-5 w-full max-w-xl mx-2 sm:mx-4 shadow-2xl animate-modalIn">
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
    </>
  );
};

export default Reports;
