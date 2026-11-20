import React, {
  useState,
  useEffect,
  useCallback,
  useRef,
  useMemo,
} from 'react';
import {
  X,
  Sparkles,
  AlertCircle,
  CheckCircle2,
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
  const [explanationState, setExplanationState] = useState<{
    identity: string;
    data: BankingRiskExplanationResponse;
  } | null>(null);

  const [errorState, setErrorState] = useState<{
    identity: string;
    message: string;
    unavailable: boolean;
  } | null>(null);

  const requestGeneration = useRef(0);
  const [retryCount, setRetryCount] = useState(0);

  const requestPayload = useMemo(() => {
    if (!profile || !risk || profile.id !== risk.asset_id) {
      return null;
    }

    return {
      system_id: profile.id,
      system_name: profile.name,
      priority_score: risk.priority_score,
      priority_band: risk.priority_band_label,
      quantum_risk_level:
        risk.technical_risk?.quantum_risk_label || 'HIGH',
      classical_risk_level:
        risk.technical_risk?.classical_risk_label || 'MEDIUM',
      criticality: String(profile.criticality || 'HIGH'),
      data_sensitivity: String(profile.data_sensitivity || 'HIGH'),
      data_lifetime: String(profile.data_lifetime || 'LONG'),
      exposure: String(profile.exposure || 'INTERNAL'),
      migration_effort: String(profile.migration_effort || 'MEDIUM'),
      top_findings: (risk.contributors || []).map(
        (contributor) =>
          contributor.label ||
          contributor.factor ||
          contributor.description ||
          'Unspecified risk contributor'
      ),
      weak_links: risk.key_protection?.weak_links || [],
      evidence_gaps: (profile.evidence_gaps || []).map(
        (gap) => gap.description
      ),
    };
  }, [profile, risk]);

  const requestIdentity = requestPayload
    ? JSON.stringify(requestPayload)
    : null;

  const explanation =
    explanationState?.identity === requestIdentity
      ? explanationState.data
      : null;

  const errorMessage =
    errorState?.identity === requestIdentity
      ? errorState.message
      : null;

  const isUnavailable =
    errorState?.identity === requestIdentity
      ? errorState.unavailable
      : false;

  const hasValidSelection = Boolean(requestPayload);

  const isLoading =
    isOpen &&
    hasValidSelection &&
    !explanation &&
    !errorMessage &&
    !isUnavailable;

  const loadExplanation = useCallback(
    async (generation: number) => {
      if (!requestPayload || !requestIdentity) return;

      try {
        const result: AIExplanationResult<BankingRiskExplanationResponse> =
          await explainBankingRisk(requestPayload);

        if (generation !== requestGeneration.current) return;

        if (result.success && result.data) {
          setExplanationState({
            identity: requestIdentity,
            data: result.data,
          });
        } else if (!result.is_available) {
          setErrorState({
            identity: requestIdentity,
            message:
              result.error ||
              'AI provider is not configured. Configure GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY to enable.',
            unavailable: true,
          });
        } else {
          setErrorState({
            identity: requestIdentity,
            message: result.error || 'Unable to generate risk explanation.',
            unavailable: false,
          });
        }
      } catch (err: unknown) {
        if (generation !== requestGeneration.current) return;

        setErrorState({
          identity: requestIdentity,
          message:
            err instanceof Error
              ? err.message
              : 'An unexpected error occurred while communicating with the AI service.',
          unavailable: false,
        });
      }
    },
    [requestPayload, requestIdentity]
  );

  useEffect(() => {
    if (!isOpen || !hasValidSelection) return;

    const generation = ++requestGeneration.current;

    const timeoutId = window.setTimeout(() => {
      void loadExplanation(generation);
    }, 0);

    return () => {
      window.clearTimeout(timeoutId);
      requestGeneration.current += 1;
    };
  }, [
    isOpen,
    hasValidSelection,
    requestIdentity,
    retryCount,
    loadExplanation,
  ]);

  const handleRetry = () => {
    setExplanationState(null);
    setErrorState(null);
    setRetryCount((count) => count + 1);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-slate-900/50 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="relative w-full max-w-3xl bg-white rounded-2xl shadow-2xl border border-slate-200 overflow-hidden flex flex-col max-h-[90vh]">
        <div className="px-6 py-4.5 border-b border-slate-100 flex items-center justify-between bg-gradient-to-r from-slate-50 via-white to-indigo-50/30">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-100 flex items-center justify-center text-[#5755D9]">
              <Sparkles className="w-4 h-4 text-[#5755D9]" />
            </div>
            <div>
              <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-[#5755D9]">
                AI Banking Risk Intelligence
              </span>
              <h3 className="text-base font-bold text-slate-900 leading-tight">
                {profile?.name || 'Banking System'} — Risk Explanation
              </h3>
              <p className="text-[10px] text-slate-400 font-mono mt-0.5">
                {profile?.id || 'Unknown system'}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition cursor-pointer"
            aria-label="Close risk explanation"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 overflow-y-auto space-y-5">
          {!hasValidSelection && (
            <div className="p-5 rounded-xl border border-amber-200 bg-amber-50">
              <div className="flex items-center gap-2 mb-2">
                <AlertCircle className="w-5 h-5 text-amber-600" />
                <h4 className="text-sm font-bold text-amber-900">
                  Banking Profile Unavailable
                </h4>
              </div>
              <p className="text-xs text-amber-800 leading-relaxed">
                A matching banking profile and risk assessment are required
                to generate an AI explanation. The deterministic risk
                assessment has not been changed.
              </p>
            </div>
          )}

          {risk && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-[9px] uppercase tracking-wider text-slate-500 font-bold block">
                  Priority Score
                </span>
                <span className="text-xl font-bold text-slate-900">
                  {risk.priority_score}
                </span>
              </div>
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-[9px] uppercase tracking-wider text-slate-500 font-bold block">
                  Priority Band
                </span>
                <span className="text-sm font-bold text-slate-900">
                  {risk.priority_band_label}
                </span>
              </div>
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-[9px] uppercase tracking-wider text-slate-500 font-bold block">
                  Quantum Risk
                </span>
                <span className="text-sm font-bold text-slate-900">
                  {risk.technical_risk?.quantum_risk_label || 'Unknown'}
                </span>
              </div>
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-[9px] uppercase tracking-wider text-slate-500 font-bold block">
                  Criticality
                </span>
                <span className="text-sm font-bold text-slate-900">
                  {profile?.criticality || 'Unknown'}
                </span>
              </div>
            </div>
          )}

          {isLoading && (
            <div className="py-14 flex flex-col items-center justify-center text-center">
              <div className="w-10 h-10 rounded-full border-2 border-indigo-100 border-t-[#5755D9] animate-spin mb-4" />
              <h4 className="text-sm font-bold text-slate-800">
                Analyzing Banking Risk
              </h4>
              <p className="text-xs text-slate-500 mt-1 max-w-sm">
                Generating an AI explanation from the deterministic risk
                assessment and available evidence.
              </p>
            </div>
          )}

          {isUnavailable && (
            <div className="p-5 rounded-xl border border-amber-200 bg-amber-50">
              <div className="flex items-center gap-2 mb-2">
                <AlertCircle className="w-5 h-5 text-amber-600" />
                <h4 className="text-sm font-bold text-amber-900">
                  AI Provider Unavailable
                </h4>
              </div>
              <p className="text-xs text-amber-800 leading-relaxed">
                {errorMessage}
              </p>
              <p className="text-[10px] text-amber-700 mt-3">
                The deterministic risk assessment remains available. AI is
                optional and does not affect risk scores or findings.
              </p>
            </div>
          )}

          {errorMessage && !isUnavailable && (
            <div className="p-5 rounded-xl border border-rose-200 bg-rose-50">
              <div className="flex items-center gap-2 mb-2">
                <AlertCircle className="w-5 h-5 text-rose-600" />
                <h4 className="text-sm font-bold text-rose-900">
                  Explanation Failed
                </h4>
              </div>
              <p className="text-xs text-rose-800 leading-relaxed">
                {errorMessage}
              </p>
            </div>
          )}

          {(errorMessage || isUnavailable) && (
            <div className="flex justify-end">
              <button
                type="button"
                onClick={handleRetry}
                className="px-4 py-2 rounded-lg bg-[#5755D9] text-white text-xs font-bold hover:bg-[#4644B8] transition cursor-pointer"
              >
                Retry Explanation
              </button>
            </div>
          )}

          {explanation && (
            <div className="space-y-5">
              <div className="p-4 rounded-xl bg-indigo-50/70 border border-indigo-100">
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle2 className="w-4 h-4 text-indigo-600" />
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-900">
                    Risk Rationale
                  </h4>
                </div>
                <p className="text-sm text-slate-700 leading-relaxed">
                  {explanation.score_rationale}
                </p>
              </div>

              <div className="space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500">
                  Contributing Factors
                </h4>
                <ul className="space-y-2">
                  {explanation.contributing_factors.map((factor, index) => (
                    <li
                      key={`${factor}-${index}`}
                      className="p-3 rounded-lg border border-slate-200 bg-white text-xs text-slate-700 leading-relaxed"
                    >
                      {factor}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                <div className="p-3.5 rounded-xl bg-white border border-slate-200/80 space-y-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-slate-500 block">
                    Severity Weighting
                  </span>
                  <p className="text-xs text-slate-700 leading-relaxed">
                    {explanation.severity_weighting_explanation}
                  </p>
                </div>
                <div className="p-3.5 rounded-xl bg-white border border-slate-200/80 space-y-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-slate-500 block">
                    Upgrade Queue Position
                  </span>
                  <p className="text-xs text-slate-700 leading-relaxed">
                    {explanation.upgrade_queue_position_reason}
                  </p>
                </div>
              </div>

              {explanation.supporting_evidence.length > 0 && (
                <div className="p-4 rounded-xl border border-emerald-200 bg-emerald-50/50">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-900 mb-2">
                    Supporting Evidence
                  </h4>
                  <ul className="space-y-1.5">
                    {explanation.supporting_evidence.map((item, index) => (
                      <li
                        key={`${item}-${index}`}
                        className="text-xs text-emerald-800 flex gap-2"
                      >
                        <span>•</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {explanation.evidence_gaps_needed.length > 0 && (
                <div className="p-4 rounded-xl border border-amber-200 bg-amber-50/50">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-amber-900 mb-2">
                    Evidence Gaps
                  </h4>
                  <ul className="space-y-1.5">
                    {explanation.evidence_gaps_needed.map((gap, index) => (
                      <li
                        key={`${gap}-${index}`}
                        className="text-xs text-amber-800 flex gap-2"
                      >
                        <span>•</span>
                        <span>{gap}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="p-2.5 rounded-lg bg-slate-100 text-slate-500 text-[10px] font-mono text-center">
                {explanation.advisory_disclaimer}
              </div>
            </div>
          )}
        </div>

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
