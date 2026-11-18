import React, { useState, useEffect } from 'react';
import {
  X,
  Sparkles,
  ShieldAlert,
  AlertCircle,
  CheckCircle2,
  RefreshCw,
  HelpCircle,
  Layers,
  ArrowRight,
} from 'lucide-react';
import { explainBankingRisk } from '../../services/api';
import type {
  BankingRiskAssessment,
  BankingSystemProfile,
  BankingRiskExplanationResponse,
  AIExplanationResult,
} from '../../types/scan';

interface AIBankingRiskModalProps {
  isOpen: boolean;
  onClose: () => void;
  profile?: BankingSystemProfile | null;
  risk?: BankingRiskAssessment | null;
}

export const AIBankingRiskModal: React.FC<AIBankingRiskModalProps> = ({
  isOpen,
  onClose,
  profile,
  risk,
}) => {
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [explanation, setExplanation] = useState<BankingRiskExplanationResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isUnavailable, setIsUnavailable] = useState<boolean>(false);

  useEffect(() => {
    if (isOpen && profile && risk && !explanation) {
      loadExplanation();
    }
  }, [isOpen, profile, risk]);

  const loadExplanation = async () => {
    if (!profile || !risk) return;

    setIsLoading(true);
    setErrorMessage(null);
    setIsUnavailable(false);

    try {
      const payload = {
        system_id: profile.id,
        system_name: profile.name,
        priority_score: risk.priority_score,
        priority_band: risk.priority_band_label,
        quantum_risk_level: risk.technical_risk?.quantum_risk_label || 'HIGH',
        classical_risk_level: risk.technical_risk?.classical_risk_label || 'MEDIUM',
        criticality: String(profile.criticality || 'HIGH'),
        data_sensitivity: String(profile.data_sensitivity || 'HIGH'),
        data_lifetime: String(profile.data_lifetime || 'LONG'),
        exposure: String(profile.exposure || 'INTERNAL'),
        migration_effort: String(profile.migration_effort || 'MEDIUM'),
        top_findings: (risk.contributors || []).map((c) => c.title),
        weak_links: risk.key_protection?.weak_links || [],
        evidence_gaps: (profile.evidence_gaps || []).map((g) => g.description),
      };

      const result: AIExplanationResult<BankingRiskExplanationResponse> = await explainBankingRisk(payload);

      if (result.success && result.data) {
        setExplanation(result.data);
      } else if (!result.is_available) {
        setIsUnavailable(true);
        setErrorMessage(result.error || 'AI provider is not configured. Configure GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY to enable.');
      } else {
        setErrorMessage(result.error || 'Unable to generate risk explanation.');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'An unexpected error occurred while communicating with AI service.');
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
                  AI Risk Reasoning
                </span>
                <span className="text-[11px] text-slate-400 font-mono">· {profile?.id}</span>
              </div>
              <h3 className="text-base font-bold text-slate-900 leading-tight">
                {profile?.name} &mdash; Migration Priority Rationale
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

        {/* Authoritative Badge Banner */}
        <div className="px-6 py-2.5 bg-indigo-50/60 border-b border-indigo-100/60 flex items-center justify-between text-xs font-mono">
          <div className="flex items-center space-x-2 text-indigo-950 font-medium">
            <span>Authoritative Deterministic Priority:</span>
            <span className="px-2 py-0.5 rounded bg-[#5755D9] text-white font-bold">
              {risk?.priority_score}/100 ({risk?.priority_band_label})
            </span>
          </div>
          <span className="text-slate-500 hidden sm:inline text-[11px]">
            AI explains, never recalculates
          </span>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-5 text-xs text-slate-700">
          {isLoading && (
            <div className="py-16 flex flex-col items-center justify-center space-y-3 text-center">
              <div className="w-7 h-7 border-2 border-indigo-200 border-t-[#5755D9] rounded-full animate-spin" />
              <p className="text-xs text-slate-600 font-mono">
                Synthesizing multi-dimensional risk factors and queue placement reasoning...
              </p>
            </div>
          )}

          {!isLoading && isUnavailable && (
            <div className="p-5 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 space-y-2">
              <div className="flex items-center space-x-2 font-semibold text-sm">
                <AlertCircle className="w-4 h-4 text-amber-600 shrink-0" />
                <span>AI Advisory Service Offline</span>
              </div>
              <p className="text-xs leading-relaxed text-amber-800">
                {errorMessage || 'AI provider is not configured. The deterministic banking risk score and priority band remain authoritative and fully operational.'}
              </p>
              <div className="pt-2 text-[11px] font-mono text-amber-700">
                Configure GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY in backend environment to enable intelligent explanations.
              </div>
            </div>
          )}

          {!isLoading && errorMessage && !isUnavailable && (
            <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 flex items-center justify-between">
              <span>{errorMessage}</span>
              <button
                type="button"
                onClick={loadExplanation}
                className="px-2.5 py-1 rounded bg-white border border-rose-300 text-rose-700 hover:bg-rose-100 transition cursor-pointer"
              >
                Retry
              </button>
            </div>
          )}

          {!isLoading && explanation && (
            <div className="space-y-4">
              {/* Score Rationale Card */}
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/80 space-y-1.5">
                <span className="text-[10px] uppercase font-mono font-bold text-slate-500 block">
                  Deterministic Score Rationale
                </span>
                <p className="text-slate-800 leading-relaxed text-[13px]">{explanation.score_rationale}</p>
              </div>

              {/* Contributing Deterministic Factors */}
              <div className="space-y-2">
                <span className="text-[10px] uppercase font-mono font-bold text-slate-500 block">
                  Contributing Factors from Risk Engine
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {explanation.contributing_factors.map((factor, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-white border border-slate-200/80 flex items-start space-x-2"
                    >
                      <CheckCircle2 className="w-4 h-4 text-[#5755D9] shrink-0 mt-0.5" />
                      <span className="text-slate-700 leading-normal">{factor}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Weighting & Queue Placement */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                <div className="p-3.5 rounded-xl bg-white border border-slate-200/80 space-y-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-slate-500 block">
                    Severity & Exposure Weighting
                  </span>
                  <p className="text-slate-700 leading-relaxed">
                    {explanation.severity_weighting_explanation}
                  </p>
                </div>

                <div className="p-3.5 rounded-xl bg-white border border-slate-200/80 space-y-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-indigo-900 block">
                    Upgrade Queue Placement Reason
                  </span>
                  <p className="text-slate-700 leading-relaxed">
                    {explanation.upgrade_queue_position_reason}
                  </p>
                </div>
              </div>

              {/* Evidence Gaps & Next Steps */}
              {explanation.evidence_gaps_needed && explanation.evidence_gaps_needed.length > 0 && (
                <div className="p-3.5 rounded-xl bg-amber-50/50 border border-amber-200/70 space-y-2">
                  <span className="text-[10px] uppercase font-mono font-bold text-amber-800 block">
                    Internal Verification Gaps (Required to Confirm Posture)
                  </span>
                  <ul className="list-disc list-inside space-y-1 text-slate-700 text-[11px]">
                    {explanation.evidence_gaps_needed.map((gap, idx) => (
                      <li key={idx}>{gap}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Disclaimer */}
              <div className="p-2.5 rounded-lg bg-slate-100 text-slate-500 text-[10px] font-mono text-center">
                {explanation.advisory_disclaimer}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-slate-100 bg-slate-50/80 flex items-center justify-between text-xs">
          <span className="text-slate-500 text-[11px] font-mono">
            Grounding: NIST FIPS 203/204/205 · NSA CNSA 2.0
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

