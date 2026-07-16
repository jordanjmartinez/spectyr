import React, { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../api';
import SiemTable from './SiemTable';
import SiemCards from './SiemCards';
import {
  parseEventQuery, alertFieldValue, platformOf,
  TIME_PRESETS, withinPreset, poolAnchorMs,
} from './siemUtils';

// SIEM tab (Stage 1.5). Fetches the session event pool on the existing feed
// cadence; every filter, search, preset, and sort operates client-side on
// the cached pool. Time presets anchor to the pool's own latest timestamp
// (the frozen scenario clock), never wall time.

const Siem = ({ setSiemCount, resetTrigger, pivotQuery, onHostPivot }) => {
  const [alerts, setAlerts] = useState([]);
  const [org, setOrg] = useState({});
  const [view, setView] = useState('cards');
  const [searchTerm, setSearchTerm] = useState('');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [platformFilter, setPlatformFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [preset, setPreset] = useState('all');

  const fetchAlerts = useCallback(() => {
    apiFetch('/api/fake-events')
      .then(res => res.json())
      .then(data => setAlerts([...data].reverse()))
      .catch(() => {});
  }, []);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 2000);
    return () => clearInterval(interval);
  }, [fetchAlerts]);

  useEffect(() => {
    apiFetch('/api/endpoints')
      .then(res => res.json())
      .then(data => setOrg(data.org || {}))
      .catch(() => {});
  }, [resetTrigger]);

  useEffect(() => {
    setAlerts([]);
    setSearchTerm('');
    setSourceFilter('all');
    setPlatformFilter('all');
    setTypeFilter('all');
    setPreset('all');
    fetchAlerts();
  }, [resetTrigger, fetchAlerts]);

  // Entity pivot from the Alerts tab: prefill the search with the value.
  useEffect(() => {
    if (pivotQuery?.value) setSearchTerm(pivotQuery.value);
  }, [pivotQuery]);

  // Dropdown values derive from the cached pool, never hardcoded.
  const sources = [...new Set(alerts.map(a => a.source_type || a.detected_by).filter(Boolean))].sort();
  const platforms = [...new Set(alerts.map(platformOf))].sort();
  const eventTypes = [...new Set(alerts.map(a => a.event_type).filter(Boolean))].sort();

  const anchorMs = poolAnchorMs(alerts);
  const { fieldFilters, free } = parseEventQuery(searchTerm);
  const filtered = alerts.filter(alert => {
    if (sourceFilter !== 'all' && (alert.source_type || alert.detected_by) !== sourceFilter) return false;
    if (platformFilter !== 'all' && platformOf(alert) !== platformFilter) return false;
    if (typeFilter !== 'all' && alert.event_type !== typeFilter) return false;
    if (!withinPreset(alert, preset, anchorMs)) return false;
    for (const [field, val] of fieldFilters) {
      if (!String(alertFieldValue(alert, field)).toLowerCase().includes(val)) return false;
    }
    if (free && !JSON.stringify(alert).toLowerCase().includes(free)) return false;
    return true;
  });

  useEffect(() => {
    setSiemCount?.(filtered.length);
  }, [filtered.length, setSiemCount]);

  const selectClass =
    'px-2.5 py-2 text-xs rounded-md border border-[#d0d7de] bg-white text-[#1a2332] focus:outline-none focus:ring-2 focus:ring-[#16436b]/30';

  const filterSelect = (label, value, onChange, options) => (
    <label className="flex items-center gap-1.5 text-xs text-[#6e7781]">
      {label}
      <select value={value} onChange={e => onChange(e.target.value)} className={selectClass} aria-label={`Filter by ${label}`}>
        <option value="all">All</option>
        {options.map(o => <option key={o} value={o}>{o}</option>)}
      </select>
    </label>
  );

  const noPool = alerts.length === 0;

  return (
    <div>
      {/* Header card */}
      <div className="bg-white border border-[#e2e6ea] rounded-xl overflow-hidden mb-4">
        <div className="h-0.5" style={{ background: 'linear-gradient(to right, #16436b, #101218)' }} />
        <div className="p-4 sm:p-5 flex flex-wrap items-center gap-4">
          <div className="w-10 h-10 rounded-lg bg-[#101218] flex items-center justify-center shrink-0">
            <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" role="img" aria-label="SIEM">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
            </svg>
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h2 className="text-xl sm:text-2xl font-semibold text-[#1a2332]">SIEM</h2>
              <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-[#eef1f4] text-[#57606a]">{filtered.length}</span>
            </div>
            <p className="text-sm text-[#57606a] truncate">
              {org.name || 'ACME Corp'}: endpoint telemetry and scenario event data
            </p>
          </div>
          <div className="ml-auto flex items-center rounded-md border border-[#d0d7de] overflow-hidden" role="group" aria-label="View">
            {[['cards', 'Cards'], ['table', 'Table']].map(([key, label]) => (
              <button
                key={key}
                type="button"
                onClick={() => setView(key)}
                className={`px-3 py-1.5 text-xs font-medium transition ${
                  view === key ? 'bg-[#101218] text-white' : 'bg-white text-[#57606a] hover:bg-[#eef1f4]'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Toolbar: search, dropdown filters, time presets */}
      <div className="mb-3 flex flex-col gap-2.5">
        <div className="relative">
          <input
            type="text"
            placeholder="Search events, e.g. source_ip=10.0.1.24 event_type=4625"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            maxLength={300}
            className="w-full pl-4 pr-10 py-2 rounded-md bg-white border border-[#e2e6ea] text-[#1a2332] text-sm placeholder-[#8b949e] focus:border-[#8b949e] focus:outline-none transition-colors"
          />
          {searchTerm ? (
            <button
              onClick={() => setSearchTerm('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-[#6e7781] hover:text-[#1a2332]"
              aria-label="Clear search"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          ) : (
            <svg className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6e7781]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {filterSelect('Source', sourceFilter, setSourceFilter, sources)}
          {filterSelect('Platform', platformFilter, setPlatformFilter, platforms)}
          {filterSelect('Event Type', typeFilter, setTypeFilter, eventTypes)}
          <div className="flex items-center gap-1 ml-auto" role="group" aria-label="Time range">
            {TIME_PRESETS.map(p => (
              <button
                key={p.key}
                type="button"
                onClick={() => setPreset(p.key)}
                className={`px-2 py-1 text-xs rounded-md border transition ${
                  preset === p.key
                    ? 'bg-[#101218] text-white border-transparent'
                    : 'bg-white text-[#57606a] border-[#d0d7de] hover:bg-[#eef1f4]'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {noPool ? (
        <div
          className="p-6 rounded-xl flex flex-col items-center justify-center py-16"
          style={{ background: '#ffffff', border: '1px solid #e2e6ea', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}
        >
          <svg className="w-8 h-8 text-[#8b949e] mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 17V7m4 10V11m4 6V9M5 21h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v14a2 2 0 002 2z" />
          </svg>
          <p className="text-sm text-[#6e7781]">No events yet. Start a simulation to begin.</p>
        </div>
      ) : view === 'cards' ? (
        <SiemCards alerts={filtered} resetTrigger={resetTrigger} onHostPivot={onHostPivot} />
      ) : (
        <SiemTable alerts={filtered} resetTrigger={resetTrigger} onHostPivot={onHostPivot} />
      )}
    </div>
  );
};

export default Siem;
