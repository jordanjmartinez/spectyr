import React, { useState, useEffect } from 'react';

const IncidentReportForm = ({ initialData = {}, onSubmit, onCancel, submitting, inline = false }) => {
  const isEditing = Boolean(initialData?.id);

  const [formData, setFormData] = useState({
    title: '',
    description: '',
    severity: 'Low',
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

  const severities = ['Low', 'Medium', 'High', 'Critical'];

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

      
      <div className="space-y-3 sm:space-y-4">

        {/* Title - Clean underline style */}
        <div>
          <label className="block text-sm text-gray-300 mb-1">Title{errors.title && <span className="text-red-400"> *</span>}</label>
          <input
            name="title"
            value={formData.title}
            onChange={handleChange}
            maxLength={60}
            className="w-full bg-transparent text-sm sm:text-lg text-white placeholder-gray-600 border-b border-gray-700 focus:border-gray-500 outline-none pb-1.5 sm:pb-2 transition-colors"
          />
        </div>


        {/* Description */}
        <div>
          <label className="block text-sm text-gray-300 mb-1">Description{errors.description && <span className="text-red-400"> *</span>}</label>
          <textarea
            name="description"
            value={formData.description}
            onChange={handleChange}
            maxLength={300}
            rows={2}
            className="w-full bg-[#161b22] text-sm sm:text-base text-white placeholder-gray-600 border border-gray-700 focus:border-gray-500 rounded-md px-3 py-2 outline-none transition-colors resize-none"
          />
        </div>

        <div>
          <label className="block text-sm text-gray-300 mb-1">Affected Systems</label>
          <input
            name="affected_hosts"
            value={formData.affected_hosts}
            onChange={handleChange}
            maxLength={100}
            className="w-full bg-transparent text-sm sm:text-base text-white placeholder-gray-600 border-b border-gray-700 focus:border-gray-500 outline-none pb-2 transition-colors"
          />
        </div>

        <div>
          <label className="block text-sm text-gray-300 mb-1">Mitigation Steps</label>
          <textarea
            name="mitigation"
            value={formData.mitigation}
            onChange={handleChange}
            maxLength={200}
            rows={2}
            className="w-full bg-[#161b22] text-sm sm:text-base text-white placeholder-gray-600 border border-gray-700 rounded-md px-3 py-2 outline-none focus:border-gray-500 transition-colors resize-none"
          />
        </div>

        {/* MITRE ATT&CK & Kill Chain Phase - Side by side dropdowns */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm text-gray-300 mb-1">MITRE ATT&CK</label>
            <select
              name="mitre_tactic"
              value={formData.mitre_tactic}
              onChange={handleChange}
              className="w-full bg-[#161b22] text-sm sm:text-base text-white border border-gray-700 focus:border-gray-500 rounded-md px-3 py-2 outline-none transition-colors appearance-none cursor-pointer"
              style={{ backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%239ca3af'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M19 9l-7 7-7-7'/%3E%3C/svg%3E")`, backgroundRepeat: 'no-repeat', backgroundPosition: 'right 0.5rem center', backgroundSize: '1.25rem' }}
            >
              <option value="">Select tactic...</option>
              {mitreTactics.map(tactic => (
                <option key={tactic} value={tactic}>{tactic}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm text-gray-300 mb-1">Kill Chain Phase</label>
            <select
              name="kill_chain"
              value={formData.kill_chain}
              onChange={handleChange}
              className="w-full bg-[#161b22] text-sm sm:text-base text-white border border-gray-700 focus:border-gray-500 rounded-md px-3 py-2 outline-none transition-colors appearance-none cursor-pointer"
              style={{ backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%239ca3af'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M19 9l-7 7-7-7'/%3E%3C/svg%3E")`, backgroundRepeat: 'no-repeat', backgroundPosition: 'right 0.5rem center', backgroundSize: '1.25rem' }}
            >
              <option value="">Select phase...</option>
              {killChainPhases.map(phase => (
                <option key={phase} value={phase}>{phase}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Actions */}
        <div className="flex justify-end gap-3 pt-2 sm:pt-3">
          <button
            onClick={onCancel}
            className="px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md border transition bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600 focus:outline-none focus:ring-2 focus:ring-gray-500"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={isSubmitting}
            className={`px-2 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm font-medium rounded-md border transition focus:outline-none focus:ring-2 focus:ring-gray-500 ${
              isSubmitting
                ? 'bg-[#21262d] text-gray-500 border-gray-700 cursor-not-allowed'
                : 'bg-[#21262d] hover:bg-[#30363d] text-gray-200 border-gray-600'
            }`}
          >
            {isSubmitting ? 'Saving...' : initialData?.id ? 'Save Report' : 'Create Report'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default IncidentReportForm;
