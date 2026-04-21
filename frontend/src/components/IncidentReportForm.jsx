import React, { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';

const IncidentReportForm = ({ initialData = {}, onSubmit, onCancel, submitting, inline = false }) => {
  const isEditing = Boolean(initialData?.id);

  const [formData, setFormData] = useState({
    title: '',
    description: '',
    severity: 'Low',
    mitre_tactic: '',
    affected_hosts: '',
    mitigation: '',
    status: 'Open',
    timestamp: new Date().toISOString(),
    id: '',
    scenario_id: '',
  });

  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [mitreTacticsSelected, setMitreTacticsSelected] = useState([]);
  const [mitreDropdownOpen, setMitreDropdownOpen] = useState(false);
  const [mitreDropdownPos, setMitreDropdownPos] = useState(null);
  const [isMobile, setIsMobile] = useState(
    () => typeof window !== 'undefined' && window.matchMedia('(max-width: 639px)').matches
  );
  const mitreDropdownRef = useRef(null);
  const mitreTriggerRef = useRef(null);

  useEffect(() => {
    if (initialData && Object.keys(initialData).length > 0) {
      setFormData({
        title: initialData.title || '',
        description: initialData.description || '',
        severity: initialData.severity || '',
        mitre_tactic: initialData.mitre_tactic || '',
        affected_hosts: initialData.affected_hosts || '',
        mitigation: initialData.mitigation || '',
        status: initialData.status || 'Open',
        timestamp: initialData.timestamp || new Date().toISOString(),
        id: initialData.id || '',
        scenario_id: initialData.scenario_id || '',
      });
      const incoming = initialData.mitre_tactic || '';
      setMitreTacticsSelected(
        incoming ? incoming.split(',').map(s => s.trim()).filter(Boolean) : []
      );
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialData?.id, initialData?.scenario_id]);

  useEffect(() => {
    setFormData(prev => ({ ...prev, mitre_tactic: mitreTacticsSelected.join(', ') }));
  }, [mitreTacticsSelected]);

  useEffect(() => {
    const mql = window.matchMedia('(max-width: 639px)');
    const handler = (e) => setIsMobile(e.matches);
    mql.addEventListener('change', handler);
    return () => mql.removeEventListener('change', handler);
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: null }));
    }
  };

  const validateForm = () => {
    const newErrors = {};
    if (!formData.title.trim()) newErrors.title = "Required";
    if (!formData.severity) newErrors.severity = "Required";
    if (!formData.description.trim()) newErrors.description = "Required";
    if (!formData.mitigation.trim()) newErrors.mitigation = "Required";

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async () => {
    if (isSubmitting) return;
    if (!validateForm()) return;
    setIsSubmitting(true);
    await onSubmit(formData);
  };

  const VISIBLE_MITRE_CHIPS = isMobile ? 2 : 3;
  const mitreTactics = [
    'Reconnaissance',
    'Resource Development',
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command & Control',
    'Exfiltration',
    'Impact',
  ];

  const inputClass = "w-full bg-[#0d1117] text-xs sm:text-sm text-white placeholder-gray-600 border border-gray-700 focus:border-[#5882b4] rounded-md px-3 py-2 outline-none transition-colors";
  const requiredMark = (fieldName) => (
    <span className={errors[fieldName] ? 'text-red-400' : 'text-gray-500'}> *</span>
  );

  return (
    <div className={`text-white ${inline ? 'w-full' : 'p-8 w-full max-w-2xl bg-[#161b22] rounded-xl border border-gray-700 shadow-2xl'}`}>
      {/* Header: title + close X */}
      <div className="relative mb-4">
        <h2 className="text-base sm:text-lg font-medium text-white pr-8">Incident Report</h2>
        <button
          type="button"
          onClick={onCancel}
          aria-label="Close"
          className="absolute top-0 right-0 -mt-1 -mr-1 p-1 text-gray-400 hover:text-white transition-colors"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      {/* Gradient divider (matches Post-Incident Review) */}
      <div className="mb-5" style={{ height: '1px', background: 'linear-gradient(to right, rgba(88,130,180,0.3), transparent)' }} />

      {/* Form fields */}
      <div className="space-y-4">
        <div>
          <label className="block text-xs text-gray-300 mb-1">Title{requiredMark('title')}</label>
          <input
            name="title"
            value={formData.title}
            onChange={handleChange}
            maxLength={60}
            className={inputClass}
          />
        </div>

        <div>
          <label className="block text-xs text-gray-300 mb-1">Description{requiredMark('description')}</label>
          <textarea
            name="description"
            value={formData.description}
            onChange={handleChange}
            maxLength={300}
            rows={5}
            className={`${inputClass} resize-none`}
          />
        </div>

        <div>
          <label className="block text-xs text-gray-300 mb-1">Affected Systems</label>
          <input
            name="affected_hosts"
            value={formData.affected_hosts}
            onChange={handleChange}
            maxLength={100}
            className={inputClass}
          />
        </div>

        <div>
          <label className="block text-xs text-gray-300 mb-1">Mitigation Steps{requiredMark('mitigation')}</label>
          <textarea
            name="mitigation"
            value={formData.mitigation}
            onChange={handleChange}
            maxLength={300}
            rows={5}
            className={`${inputClass} resize-none`}
          />
        </div>

        <div>
          <label className="block text-xs text-gray-300 mb-1">MITRE ATT&CK</label>
          <div className="relative" ref={mitreDropdownRef}>
            <button
              ref={mitreTriggerRef}
              type="button"
              onClick={() => {
                if (mitreDropdownOpen) {
                  setMitreDropdownOpen(false);
                  return;
                }
                const rect = mitreTriggerRef.current.getBoundingClientRect();
                const dropdownHeight = 256;
                const spaceBelow = window.innerHeight - rect.bottom;
                const spaceAbove = rect.top;
                const openUpward = spaceBelow < dropdownHeight && spaceAbove > spaceBelow;
                setMitreDropdownPos({
                  ...(openUpward
                    ? { bottom: window.innerHeight - rect.top + 4 }
                    : { top: rect.bottom + 4 }),
                  left: rect.left,
                  width: rect.width,
                });
                setMitreDropdownOpen(true);
              }}
              className={`${inputClass} cursor-pointer text-left flex items-center justify-between gap-2 min-h-[42px]`}
            >
              <div className="flex flex-nowrap items-center gap-1.5 flex-1 overflow-hidden">
                {mitreTacticsSelected.length === 0 ? (
                  <span className="text-gray-600">Select tactics...</span>
                ) : (
                  <>
                    {mitreTacticsSelected.slice(0, VISIBLE_MITRE_CHIPS).map(tactic => (
                      <span
                        key={tactic}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] bg-[#21262d] border border-gray-600 text-gray-200 flex-shrink-0 max-w-[140px]"
                      >
                        <span className="truncate">{tactic}</span>
                        <span
                          onClick={(e) => {
                            e.stopPropagation();
                            setMitreTacticsSelected(prev => prev.filter(t => t !== tactic));
                          }}
                          className="text-gray-400 hover:text-white cursor-pointer flex-shrink-0"
                          aria-label={`Remove ${tactic}`}
                        >
                          ×
                        </span>
                      </span>
                    ))}
                    {mitreTacticsSelected.length > VISIBLE_MITRE_CHIPS && (
                      <span className="text-[11px] text-gray-400 flex-shrink-0">
                        +{mitreTacticsSelected.length - VISIBLE_MITRE_CHIPS} more
                      </span>
                    )}
                  </>
                )}
              </div>
              <svg
                className={`w-4 h-4 text-gray-400 flex-shrink-0 transition-transform ${mitreDropdownOpen ? 'rotate-180' : ''}`}
                fill="none" stroke="currentColor" viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            {mitreDropdownOpen && mitreDropdownPos && createPortal(
              <>
                <div className="fixed inset-0 z-[60]" onClick={() => setMitreDropdownOpen(false)} />
                <div
                  style={{
                    position: 'fixed',
                    ...(mitreDropdownPos.top !== undefined
                      ? { top: `${mitreDropdownPos.top}px` }
                      : { bottom: `${mitreDropdownPos.bottom}px` }),
                    left: `${mitreDropdownPos.left}px`,
                    width: `${mitreDropdownPos.width}px`,
                    zIndex: 70,
                  }}
                  className="bg-[#0d1117] border border-gray-700 rounded py-1 max-h-64 overflow-y-auto [&::-webkit-scrollbar]:hidden [scrollbar-width:none]"
                >
                  {mitreTactics.map(tactic => {
                    const checked = mitreTacticsSelected.includes(tactic);
                    return (
                      <button
                        key={tactic}
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setMitreTacticsSelected(prev =>
                            checked ? prev.filter(t => t !== tactic) : [...prev, tactic]
                          );
                        }}
                        className="w-full flex items-center gap-2 text-left px-3 py-2 text-xs text-gray-300 hover:bg-gray-700 transition"
                      >
                        <span className={`w-3.5 h-3.5 flex-shrink-0 rounded border ${checked ? 'bg-gray-300 border-gray-300' : 'border-gray-600'}`} />
                        {tactic}
                      </button>
                    );
                  })}
                </div>
              </>,
              document.body
            )}
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="mt-5 flex justify-end gap-2">
        <button
          onClick={onCancel}
          disabled={isSubmitting}
          className="inline-flex items-center justify-center px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600 focus:outline-none focus:ring-2 focus:ring-gray-500 disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          onClick={handleSubmit}
          disabled={isSubmitting}
          className="inline-flex items-center justify-center px-2 sm:px-3 py-1.5 sm:py-2 text-xs font-medium rounded-md border transition bg-[#5882b4] hover:bg-[#7aa4d4] text-white border-[#5882b4] hover:border-[#7aa4d4] focus:outline-none focus:ring-2 focus:ring-[#5882b4] disabled:opacity-50"
        >
          {isSubmitting ? 'Saving...' : isEditing ? 'Save' : 'Submit'}
        </button>
      </div>
    </div>
  );
};

export default IncidentReportForm;
