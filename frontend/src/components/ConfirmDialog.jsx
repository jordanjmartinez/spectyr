import React from 'react';

// Shared confirm dialog for response actions (Stage 3a). Charcoal primary
// button per the chrome palette; color stays reserved for severity meaning.
const ConfirmDialog = ({ open, title, body, confirmLabel = 'Confirm', onConfirm, onCancel, busy = false }) => {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" role="dialog" aria-modal="true">
      <div className="bg-white rounded-xl border border-[#e2e6ea] shadow-xl w-full max-w-sm overflow-hidden">
        <div className="p-5">
          <h3 className="text-base font-semibold text-[#1a2332]">{title}</h3>
          <p className="mt-2 text-sm text-[#57606a]">{body}</p>
          <div className="mt-5 flex justify-end gap-2">
            <button
              type="button"
              onClick={onCancel}
              disabled={busy}
              className="px-3 py-1.5 text-sm rounded-md border border-[#d0d7de] text-[#57606a] hover:bg-[#eef1f4] disabled:opacity-60"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={onConfirm}
              disabled={busy}
              className="px-3 py-1.5 text-sm rounded-md bg-[#101218] text-white hover:bg-[#1a2332] disabled:opacity-60"
            >
              {confirmLabel}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ConfirmDialog;
