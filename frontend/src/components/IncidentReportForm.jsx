import React, { useState, useEffect } from 'react';

const IncidentReportForm = ({ initialData = {}, onSubmit, onCancel, submitting, inline = false }) => {
  const isEditing = Boolean(initialData?.id);

  const [formData, setFormData] = useState({
    title: '',
    description: '',
    severity: '',
    mitre_tactic: '',
    kill_chain: '',
    affected_hosts: '',
    mitigation: '',
    status: 'Open',
    timestamp: new Date().toISOString(),
    id: '',
    scenario_id: '',
  });

  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (initialData && Object.keys(initialData).length > 0) {
      setFormData({
        title: initialData.title || '',
        description: initialData.description || '',
        severity: initialData.severity || '',
        mitre_tactic: initialData.mitre_tactic || '',
        kill_chain: initialData.kill_chain || '',
        affected_hosts: initialData.affected_hosts || '',
        mitigation: initialData.mitigation || '',
        status: initialData.status || 'Open',
        timestamp: initialData.timestamp || new Date().toISOString(),
        id: initialData.id || '',
        scenario_id: initialData.scenario_id || '',
      });
    }
  }, [initialData]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: null }));
    }
  };

  const validateForm = () => {
    const newErrors = {};
    if (!formData.title.trim()) newErrors.title = "Required";
    if (!formData.severity) newErrors.severity = "Required";
    if (!formData.description.trim()) newErrors.description = "Required";

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async () => {
    if (isSubmitting) return;
    if (!validateForm()) return;
    setIsSubmitting(true);
    await onSubmit(formData);
  };

  const severities = ['Critical', 'High', 'Medium', 'Low'];

  const killChainPhases = [
    'Reconnaissance',
    'Weaponization',
    'Delivery',
    'Exploitation',
    'Installation',
    'Command & Control',
    'Actions on Objectives',
  ];

  const mitreTactics = [
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

  return (
    <div className={`text-white ${inline ? 'w-full' : 'p-8 w-full max-w-2xl bg-[#161b22] rounded-xl border border-gray-700 shadow-2xl'}`}>

      
      <div className="space-y-6">

        {/* Title - Clean underline style */}
        <div>
          <label className="block text-base text-gray-300 mb-2">Title{errors.title && <span className="text-red-400"> *</span>}</label>
          <input
            name="title"
            value={formData.title}
            onChange={handleChange}
            maxLength={60}
            className="w-full bg-transparent text-lg text-white placeholder-gray-600 border-b border-gray-700 focus:border-gray-500 outline-none pb-2 transition-colors"
          />
        </div>

        {/* Severity - Pill selection */}
        <div>
          <label className="block text-base text-gray-300 mb-3">Severity{errors.severity && <span className="text-red-400"> *</span>}</label>
          <div className="flex flex-wrap gap-2">
            {severities.map(sev => (
              <button
                key={sev}
                type="button"
                onClick={() => {
                  setFormData(prev => ({ ...prev, severity: sev }));
                  if (errors.severity) {
                    setErrors(prev => ({ ...prev, severity: null }));
                  }
                }}
                className={`px-3 py-1.5 text-base rounded-full border transition-all ${
                  formData.severity === sev
                    ? 'bg-[#21262d] text-white border-gray-600'
                    : 'bg-[#161b22] text-gray-400 border-gray-700 hover:bg-[#30363d]'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {/* MITRE Tactic & Kill Chain - Side by side dropdowns */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-base text-gray-300 mb-2">MITRE Tactic</label>
            <select
              name="mitre_tactic"
              value={formData.mitre_tactic}
              onChange={handleChange}
              className="w-full bg-[#161b22] text-white border border-gray-700 focus:border-gray-500 rounded-md px-3 py-2 outline-none transition-colors appearance-none cursor-pointer"
              style={{ backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%239ca3af'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M19 9l-7 7-7-7'/%3E%3C/svg%3E")`, backgroundRepeat: 'no-repeat', backgroundPosition: 'right 0.5rem center', backgroundSize: '1.25rem' }}
            >
              <option value="">Select tactic...</option>
              {mitreTactics.map(tactic => (
                <option key={tactic} value={tactic}>{tactic}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-base text-gray-300 mb-2">Kill Chain</label>
            <select
              name="kill_chain"
              value={formData.kill_chain}
              onChange={handleChange}
              className="w-full bg-[#161b22] text-white border border-gray-700 focus:border-gray-500 rounded-md px-3 py-2 outline-none transition-colors appearance-none cursor-pointer"
              style={{ backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%239ca3af'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M19 9l-7 7-7-7'/%3E%3C/svg%3E")`, backgroundRepeat: 'no-repeat', backgroundPosition: 'right 0.5rem center', backgroundSize: '1.25rem' }}
            >
              <option value="">Select phase...</option>
              {killChainPhases.map(phase => (
                <option key={phase} value={phase}>{phase}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Description - Clean textarea */}
        <div>
          <label className="block text-base text-gray-300 mb-2">Description{errors.description && <span className="text-red-400"> *</span>}</label>
          <textarea
            name="description"
            value={formData.description}
            onChange={handleChange}
            maxLength={300}
            rows={3}
            className="w-full bg-[#161b22] text-white placeholder-gray-600 border border-gray-700 focus:border-gray-500 rounded-md px-3 py-2 outline-none transition-colors resize-none"
          />
        </div>

        {/* Additional fields - Only show when editing */}
        {isEditing && (
          <>
            <div>
              <label className="block text-base text-gray-300 mb-2">Affected Systems</label>
              <input
                name="affected_hosts"
                value={formData.affected_hosts}
                onChange={handleChange}
                maxLength={100}
                className="w-full bg-transparent text-white placeholder-gray-600 border-b border-gray-700 focus:border-gray-500 outline-none pb-2 transition-colors"
              />
            </div>

            <div>
              <label className="block text-base text-gray-300 mb-2">Mitigation</label>
              <textarea
                name="mitigation"
                value={formData.mitigation}
                onChange={handleChange}
                maxLength={200}
                rows={2}
                className="w-full bg-[#161b22] text-white placeholder-gray-600 border border-gray-700 rounded-md px-3 py-2 outline-none focus:border-gray-500 transition-colors resize-none"
              />
            </div>

            <div>
              <label className="block text-base text-gray-300 mb-2">Status</label>
              <div className="flex flex-wrap gap-2">
                {['Open', 'In Progress', 'Escalated', 'Resolved'].map(status => (
                  <button
                    key={status}
                    type="button"
                    onClick={() => setFormData(prev => ({ ...prev, status }))}
                    className={`px-3 py-1.5 text-base rounded-full border transition-all ${
                      formData.status === status
                        ? 'bg-[#21262d] text-white border-gray-600'
                        : 'bg-[#161b22] text-gray-400 border-gray-700 hover:bg-[#30363d]'
                    }`}
                  >
                    {status}
                  </button>
                ))}
              </div>
            </div>
          </>
        )}

        {/* Actions */}
        <div className="flex justify-end gap-3 pt-6">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-base font-medium rounded-md border transition bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600 focus:outline-none focus:ring-2 focus:ring-gray-500"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={isSubmitting}
            className={`px-4 py-2 text-base font-medium rounded-md border transition focus:outline-none focus:ring-2 focus:ring-gray-500 ${
              isSubmitting
                ? 'bg-[#21262d] text-gray-500 border-gray-700 cursor-not-allowed'
                : 'bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600'
            }`}
          >
            {isSubmitting ? 'Saving...' : 'Save Case'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default IncidentReportForm;
