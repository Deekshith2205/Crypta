import React, { useState, useEffect } from 'react';
import {
  X,
  Sparkles,
  ArrowRight,
  AlertCircle,
  CheckCircle2,
  Cpu,
  Layers,
  Network,
  Milestone,
  RefreshCw,
} from 'lucide-react';
import { adviseMigration } from '../../services/api';
import type {
  MigrationAdvisoryResponse,
  AIExplanationResult,
  RankedUpgradeItem,
  WhatIfMigrationResult,
} from '../../types/scan';

interface AIMigrationAdvisorModalProps {
  isOpen: boolean;
  onClose: () => void;
  systemId: string;
  systemName: string;
  baselineScore: number;
  baselineBand: string;
  targetPrimitive?: string;
  simulationResult?: WhatIfMigrationResult | null;
  upgradeItem?: RankedUpgradeItem | null;
}

export const AIMigrationAdvisorModal: React.FC<AIMigrationAdvisorModalProps> = ({
  isOpen,
  onClose,
  systemId,
  systemName,
  baselineScore,
  baselineBand,
  targetPrimitive = 'ML-KEM-768 / Hybrid PQC',
  simulationResult,
  upgradeItem,
}) => {
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [advisory, setAdvisory] = useState<MigrationAdvisoryResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isUnavailable, setIsUnavailable] = useState<boolean>(false);

  useEffect(() => {
    if (isOpen && !advisory) {
      loadAdvisory();
    }
  }, [isOpen, systemId]);

  const loadAdvisory = async () => {
    setIsLoading(true);
    setErrorMessage(null);
    setIsUnavailable(false);

    try {
      const payload = {
        system_id: systemId,
        system_name: systemName,
        baseline_priority_score: baselineScore,
        baseline_priority_band: baselineBand,
        target_replacement: targetPrimitive,
        simulated_changes: simulationResult?.comparison?.actions_applied || [],
        projected_priority_score: simulationResult?.after?.priority_score,
        projected_priority_band: simulationResult?.after?.priority_band_label,
        crypto_agility: upgradeItem?.crypto_agility || 'NOT_OBSERVABLE',
        migration_impact: upgradeItem?.migration_impact || 'HIGH',
        dependencies: upgradeItem?.evidence_gaps || [
          'HSM FIPS 140-3 firmware update',
          'TLS 1.3 stack update with hybrid group support',
        ],
      };

      const result: AIExplanationResult<MigrationAdvisoryResponse> = await adviseMigration(payload);

      if (result.success && result.data) {
        setAdvisory(result.data);
      } else if (!result.is_available) {
        setIsUnavailable(true);
        setErrorMessage(result.error || 'AI provider is not configured.');
      } else {
        setErrorMessage(result.error || 'Unable to generate migration advisory.');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'An unexpected error occurred while communicating with the AI service.');
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-slate-900/50 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="relative w-full max-w-3xl bg-white rounded-2xl shadow-2xl border border-slate-200 overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4.5 border-b border-slate-100 flex items-center justify-between bg-gradient-to-r from-slate-50 via-white to-indigo-50/30">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-100 flex items-center justify-center text-[#5755D9]">
              <Sparkles className="w-4 h-4 text-[#5755D9]" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-[#5755D9]">
                  AI Migration Advisor
                </span>
                <span className="text-[11px] text-slate-400 font-mono">· {systemId}</span>
              </div>
              <h3 className="text-base font-bold text-slate-900 leading-tight">
                {systemName} &mdash; Post-Quantum Roadmap Advisory
              </h3>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Priority and Target Banner */}
        <div className="px-6 py-2.5 bg-indigo-50/60 border-b border-indigo-100/60 flex items-center justify-between text-xs font-mono">
          <div className="flex items-center space-x-3">
            <span className="text-slate-600">Baseline: {baselineScore}/100 ({baselineBand})</span>
            <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-[#5755D9] font-bold">Target: {targetPrimitive}</span>
          </div>
          <span className="text-slate-400 text-[11px] hidden sm:inline">
            FIPS 203/204/205 Architecture
          </span>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-5 text-xs text-slate-700">
          {isLoading && (
            <div className="py-16 flex flex-col items-center justify-center space-y-3 text-center">
              <div className="w-7 h-7 border-2 border-indigo-200 border-t-[#5755D9] rounded-full animate-spin" />
              <p className="text-xs text-slate-600 font-mono">
                Synthesizing architectural roadmap, operational considerations, and deployment milestones...
              </p>
            </div>
          )}

          {!isLoading && isUnavailable && (
            <div className="p-5 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 space-y-2">
              <div className="flex items-center space-x-2 font-semibold text-sm">
                <AlertCircle className="w-4 h-4 text-amber-600 shrink-0" />
                <span>AI Migration Advisor Offline</span>
              </div>
              <p className="text-xs leading-relaxed text-amber-800">
                {errorMessage || 'AI provider is not configured. The deterministic migration score and what-if simulation results remain fully accessible.'}
              </p>
            </div>
          )}

          {!isLoading && errorMessage && !isUnavailable && (
            <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 flex items-center justify-between">
              <span>{errorMessage}</span>
              <button
                type="button"
                onClick={loadAdvisory}
                className="px-2.5 py-1 rounded bg-white border border-rose-300 text-rose-700 hover:bg-rose-100 transition cursor-pointer"
              >
                Retry
              </button>
            </div>
          )}

          {!isLoading && advisory && (
            <div className="space-y-4">
              {/* Migration Justification */}
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/80 space-y-1.5">
                <span className="text-[10px] uppercase font-mono font-bold text-slate-500 block">
                  Migration Justification
                </span>
                <p className="text-slate-800 leading-relaxed text-[13px]">{advisory.migration_justification}</p>
              </div>

              {/* PQC Direction & Operational Impact */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                <div className="p-3.5 rounded-xl bg-white border border-slate-200/80 space-y-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-[#5755D9] block flex items-center space-x-1">
                    <Cpu className="w-3.5 h-3.5" />
                    <span>PQC Standards Direction</span>
                  </span>
                  <p className="text-slate-700 leading-relaxed">{advisory.pqc_direction}</p>
                </div>

                <div className="p-3.5 rounded-xl bg-white border border-slate-200/80 space-y-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-slate-500 block flex items-center space-x-1">
                    <Network className="w-3.5 h-3.5" />
                    <span>Operational & Network Impact</span>
                  </span>
                  <p className="text-slate-700 leading-relaxed">{advisory.operational_impact_assessment}</p>
                </div>
              </div>

              {/* Interoperability & Testing */}
              <div className="p-3.5 rounded-xl bg-indigo-50/40 border border-indigo-100 space-y-1">
                <span className="text-[10px] uppercase font-mono font-bold text-indigo-900 block">
                  Hybrid Transition & Interoperability Considerations
                </span>
                <p className="text-slate-700 leading-relaxed">{advisory.interoperability_and_testing}</p>
              </div>

              {/* Phased Migration Sequence */}
              <div className="space-y-2">
                <span className="text-[10px] uppercase font-mono font-bold text-slate-500 block flex items-center space-x-1">
                  <Milestone className="w-3.5 h-3.5" />
                  <span>Suggested Phased Migration Milestones</span>
                </span>
                <div className="space-y-2">
                  {advisory.suggested_migration_phases.map((phase, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-white border border-slate-200/80 flex items-start space-x-3"
                    >
                      <span className="w-5 h-5 rounded-full bg-indigo-100 text-[#5755D9] font-bold flex items-center justify-center shrink-0 text-[10px] font-mono">
                        {idx + 1}
                      </span>
                      <span className="text-slate-700 leading-relaxed">{phase}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Pre-Deployment Validation Steps */}
              <div className="space-y-2">
                <span className="text-[10px] uppercase font-mono font-bold text-emerald-800 block flex items-center space-x-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Pre-Deployment Verification & Validation Checks</span>
                </span>
                <div className="p-3.5 rounded-xl bg-emerald-50/30 border border-emerald-200/70 space-y-1.5">
                  <ul className="list-disc list-inside space-y-1 text-slate-700 text-[11px]">
                    {advisory.pre_deployment_validation_steps.map((step, idx) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Disclaimer */}
              <div className="p-2.5 rounded-lg bg-slate-100 text-slate-500 text-[10px] font-mono text-center">
                {advisory.advisory_disclaimer}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-slate-100 bg-slate-50/80 flex items-center justify-between text-xs">
          <span className="text-slate-500 text-[11px] font-mono">
            Methodology: NIST FIPS 203/204/205 · NSA CNSA 2.0
          </span>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-[#5755D9] text-white font-medium hover:bg-[#4644B8] transition cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

