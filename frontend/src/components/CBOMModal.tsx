import React, { useState, useEffect } from 'react';
import { X, Copy, Check, Download, Layers, Shield, FileCode, CheckCircle2 } from 'lucide-react';
import type { CBOMDocument, CBOMComponent } from '../types/scan.ts';

interface CBOMModalProps {
  isOpen: boolean;
  onClose: () => void;
  cbom: CBOMDocument | null;
  systemName: string;
  systemId: string;
}

export const CBOMModal: React.FC<CBOMModalProps> = ({
  isOpen,
  onClose,
  cbom,
  systemName,
  systemId,
}) => {
  const [activeTab, setActiveTab] = useState<'inventory' | 'raw'>('inventory');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen || !cbom) return null;

  const jsonString = JSON.stringify(cbom, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `quantumshield-cbom-${systemId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getEvidenceStatusBadge = (status?: string) => {
    switch (status?.toUpperCase()) {
      case 'OBSERVED':
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
      case 'INFERRED':
        return 'bg-purple-50 text-purple-700 border-purple-200';
      case 'NOT_OBSERVABLE':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      default:
        return 'bg-slate-50 text-slate-600 border-slate-200';
    }
  };

  const getQuantumCategoryBadge = (level?: number) => {
    if (level === undefined || level === null) {
      return 'bg-slate-100 text-slate-600 border-slate-200';
    }
    if (level === 0) {
      return 'bg-red-50 text-red-700 border-red-200';
    }
    if (level >= 3) {
      return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    }
    return 'bg-indigo-50 text-indigo-700 border-indigo-200';
  };

  const renderComponentRow = (comp: CBOMComponent, idx: number) => {
    const cp = comp.cryptoProperties || {};
    const algoProps = cp.algorithmProperties;
    const properties = comp.properties || [];
    const propMap = properties.reduce<Record<string, string>>((acc, p) => {
      acc[p.name] = p.value;
      return acc;
    }, {});

    const sourceFile = propMap['quantumshield:source_file'] || 'Declared';
    const sourceLine = propMap['quantumshield:source_line'];
    const evidenceStatus = propMap['quantumshield:evidence_status'] || 'OBSERVED';
    const role = propMap['quantumshield:role'] || 'CRYPTOGRAPHIC_ASSET';

    return (
      <tr key={comp['bom-ref'] || idx} className="hover:bg-slate-50/80 transition-colors">
        <td className="px-4 py-3 text-xs font-semibold text-slate-900">
          <div className="flex items-center space-x-1.5">
            <span>{comp.name}</span>
          </div>
          <span className="text-[10px] font-mono text-slate-400 block truncate max-w-[200px]" title={comp['bom-ref']}>
            {comp['bom-ref']}
          </span>
        </td>
        <td className="px-4 py-3 text-xs text-slate-600 font-mono">
          <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 text-[11px] font-medium border border-slate-200">
            {cp.assetType || 'algorithm'}
          </span>
        </td>
        <td className="px-4 py-3 text-xs text-slate-600">
          <div className="text-[11px] font-mono">
            {algoProps?.primitive ? (
              <span className="text-slate-700 font-medium">{algoProps.primitive}</span>
            ) : (
              <span className="text-slate-400">N/A</span>
            )}
            {algoProps?.parameterSetIdentifier && (
              <span className="text-slate-500 ml-1">({algoProps.parameterSetIdentifier} bits)</span>
            )}
            {algoProps?.mode && <span className="text-slate-500 ml-1">[{algoProps.mode.toUpperCase()}]</span>}
          </div>
        </td>
        <td className="px-4 py-3 text-xs">
          {algoProps?.nistQuantumSecurityLevel !== undefined && algoProps?.nistQuantumSecurityLevel !== null ? (
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getQuantumCategoryBadge(
                algoProps.nistQuantumSecurityLevel
              )}`}
            >
              Cat {algoProps.nistQuantumSecurityLevel}
            </span>
          ) : (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-500 bg-slate-100 border border-slate-200">
              Classical
            </span>
          )}
        </td>
        <td className="px-4 py-3 text-xs text-slate-600">
          <div className="flex flex-col">
            <span className="font-mono text-[11px] text-slate-700 truncate max-w-[180px]" title={sourceFile}>
              {sourceFile} {sourceLine ? `:${sourceLine}` : ''}
            </span>
            <div className="flex items-center space-x-1 mt-0.5">
              <span className="text-[10px] font-mono text-slate-500 truncate max-w-[120px]">{role}</span>
              <span
                className={`text-[9px] font-mono font-semibold px-1.5 py-0.2 rounded border ${getEvidenceStatusBadge(
                  evidenceStatus
                )}`}
              >
                {evidenceStatus}
              </span>
            </div>
          </div>
        </td>
      </tr>
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs animate-in fade-in duration-150">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="cbom-modal-title"
        className="relative w-full max-w-5xl rounded-2xl bg-white border border-slate-200 shadow-2xl p-6 sm:p-7 max-h-[90vh] flex flex-col space-y-4"
      >
        {/* Header */}
        <div className="flex items-start justify-between pb-3 border-b border-slate-100 shrink-0">
          <div className="flex items-start space-x-3">
            <div className="p-2.5 rounded-xl bg-indigo-50 border border-indigo-100 text-[#5755D9] mt-0.5">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 id="cbom-modal-title" className="text-lg font-bold text-slate-900 tracking-tight">
                  Cryptographic Bill of Materials (CBOM)
                </h2>
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-indigo-50 text-[#5755D9] border border-indigo-100">
                  CycloneDX {cbom.specVersion || '1.7'}
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                System: <strong className="text-slate-700">{systemName}</strong> ({systemId}) · URN:{' '}
                <span className="font-mono text-slate-400">{cbom.serialNumber}</span>
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close CBOM dialog"
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition cursor-pointer focus-visible:ring-2 focus-visible:ring-[#5755D9]"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center justify-between border-b border-slate-100 pb-2 shrink-0">
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setActiveTab('inventory')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'inventory'
                  ? 'bg-indigo-50 text-[#5755D9] border border-indigo-200'
                  : 'text-slate-600 hover:bg-slate-100 border border-transparent'
              }`}
            >
              <Shield className="w-3.5 h-3.5" />
              <span>Cryptographic Inventory ({cbom.components.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('raw')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'raw'
                  ? 'bg-indigo-50 text-[#5755D9] border border-indigo-200'
                  : 'text-slate-600 hover:bg-slate-100 border border-transparent'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>CycloneDX 1.7 JSON</span>
            </button>
          </div>

          <div className="text-[11px] text-slate-500 font-mono">
            Invariant: Inventory, Not Risk Engine
          </div>
        </div>

        {/* Content Body */}
        {activeTab === 'inventory' ? (
          <div className="flex-1 overflow-auto rounded-xl border border-slate-200">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-semibold text-slate-600 uppercase tracking-wider">
                  <th className="px-4 py-2.5">Asset & bom-ref</th>
                  <th className="px-4 py-2.5">Asset Type</th>
                  <th className="px-4 py-2.5">Primitive & Params</th>
                  <th className="px-4 py-2.5">Quantum Security</th>
                  <th className="px-4 py-2.5">Provenance & Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {cbom.components.length > 0 ? (
                  cbom.components.map((comp, idx) => renderComponentRow(comp, idx))
                ) : (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-xs text-slate-400">
                      No cryptographic assets observed in this system configuration.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="flex-1 overflow-auto rounded-xl bg-slate-900 p-4 border border-slate-800 font-mono text-xs text-slate-200">
            <pre className="whitespace-pre">{jsonString}</pre>
          </div>
        )}

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-2 border-t border-slate-100 shrink-0">
          <div className="flex items-center space-x-2 text-xs text-slate-500 font-mono">
            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
            <span>
              CycloneDX 1.7 · {cbom.components.length} Assets · {cbom.dependencies?.length || 0} Relationships
            </span>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={handleCopy}
              className="flex items-center space-x-1.5 px-3 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium text-xs transition cursor-pointer"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4 text-slate-500" />}
              <span>{copied ? 'Copied!' : 'Copy JSON'}</span>
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center space-x-1.5 px-4 py-2 rounded-xl bg-[#18181B] hover:bg-black text-white font-medium text-xs transition cursor-pointer shadow-xs"
            >
              <Download className="w-4 h-4" />
              <span>Download CycloneDX JSON</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
