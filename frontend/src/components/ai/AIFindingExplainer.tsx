import React, { useState } from 'react';
import {
  Sparkles,
  ChevronDown,
  ChevronUp,
  AlertCircle,
  ShieldAlert,
  BookOpen,
  ArrowRight,
  Info,
  CheckCircle2,
  RefreshCw,
} from 'lucide-react';
import { explainFinding } from '../../services/api';
import type {
  QuantumFinding,
  FindingExplanationResponse,
  AIExplanationResult,
} from '../../types/scan';

interface AIFindingExplainerProps {
  finding: QuantumFinding;
}

export const AIFindingExplainer: React.FC<AIFindingExplainerProps> = ({ finding }) => {
  const [isOpen, setIsOpen] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [explanation, setExplanation] = useState<FindingExplanationResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isUnavailable, setIsUnavailable] = useState<boolean>(false);

  const fetchExplanation = async () => {
    setIsLoading(true);
    setErrorMessage(null);
    setIsUnavailable(false);

    try {
      const payload = {
        rule_id: finding.id,
        title: finding.title,
        value: finding.value || finding.algorithm || 'Declared Cryptography',
        role: finding.role || (finding.category === 'public_key' ? 'DIGITAL_SIGNATURE' : (finding.category === 'key_exchange' ? 'KEY_EXCHANGE' : 'DATA_ENCRYPTION')),
        source: finding.source || finding.observed_from || 'EXTERNAL_SCAN',
        evidence_status: (
          finding.evidence?.trim() ||
          finding.observability?.trim() ||
          'NOT_OBSERVABLE'
        ).toUpperCase(),
        severity: finding.risk_level || 'MEDIUM',
        risk: finding.quantum_threat ? 'QUANTUM' : 'CLASSICAL',
        message: finding.security_impact || finding.reason,
        recommendation: finding.recommendation,
      };

      const result: AIExplanationResult<FindingExplanationResponse> = await explainFinding(payload);

      if (result.success && result.data) {
        setExplanation(result.data);
      } else if (!result.is_available) {
        setIsUnavailable(true);
        setErrorMessage(result.error || 'AI provider is not configured. Configure GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY to enable.');
      } else {
        setErrorMessage(result.error || 'Unable to generate AI explanation.');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'An unexpected error occurred while communicating with the AI service.');
    } finally {
      setIsLoading(false);
    }
  };

  const toggleOpen = () => {
    if (!isOpen && !explanation && !isLoading) {
      fetchExplanation();
    }
    setIsOpen(!isOpen);
  };

  return (
    <div className="border-t border-slate-100 pt-3">
      {/* Trigger Button */}
      <button
        type="button"
        onClick={toggleOpen}
        className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-[#5755D9] hover:bg-indigo-50/80 border border-indigo-100 transition cursor-pointer"
      >
        <Sparkles className="w-3.5 h-3.5 text-[#5755D9]" />
        <span>{isOpen ? 'Hide AI Reasoning' : 'Explain Finding with AI'}</span>
        {isOpen ? (
          <ChevronUp className="w-3.5 h-3.5 ml-0.5 text-slate-400" />
        ) : (
          <ChevronDown className="w-3.5 h-3.5 ml-0.5 text-slate-400" />
        )}
      </button>

      {/* Expanded Content Panel */}
      {isOpen && (
        <div className="mt-3 p-4.5 rounded-xl bg-gradient-to-b from-[#FBFBFE] to-[#F8FAFC] border border-indigo-100/80 shadow-2xs space-y-4 animate-in fade-in duration-200">
          {/* Header Banner */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-indigo-100/60 gap-2">
            <div className="flex items-center space-x-2">
              <span className="w-2 h-2 rounded-full bg-[#5755D9]" />
              <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-[#5755D9]">
                AI Advisory &mdash; Informational Explanation
              </span>
            </div>
            <span className="text-[11px] text-slate-400 font-mono">
              Deterministic scanner remains authoritative
            </span>
          </div>

          {/* Loading State */}
          {isLoading && (
            <div className="py-8 flex flex-col items-center justify-center space-y-2 text-center">
              <div className="w-6 h-6 border-2 border-indigo-200 border-t-[#5755D9] rounded-full animate-spin" />
              <p className="text-xs text-slate-600 font-mono">
                Synthesizing contextual explanation against NIST FIPS and CNSA 2.0 guidelines...
              </p>
            </div>
          )}

          {/* Provider Unavailable State */}
          {!isLoading && isUnavailable && (
            <div className="p-4 rounded-xl bg-amber-50/80 border border-amber-200 text-amber-900 space-y-1.5 text-xs">
              <div className="flex items-center space-x-2 font-semibold">
                <AlertCircle className="w-4 h-4 text-amber-600 shrink-0" />
                <span>AI Advisory Layer Offline</span>
              </div>
              <p className="text-amber-800 leading-relaxed text-[11px]">
                {errorMessage || 'AI provider is not configured. The deterministic scanner findings and severity remain fully operational.'}
              </p>
              <p className="text-amber-700 text-[10px] font-mono pt-1">
                To enable AI features, set GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY in your backend environment.
              </p>
            </div>
          )}

          {/* Error State */}
          {!isLoading && errorMessage && !isUnavailable && (
            <div className="p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-xs flex items-center justify-between gap-2">
              <div className="flex items-center space-x-2">
                <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
                <span>{errorMessage}</span>
              </div>
              <button
                type="button"
                onClick={fetchExplanation}
                className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-white border border-rose-300 text-rose-700 text-[11px] font-medium hover:bg-rose-100 transition cursor-pointer"
              >
                <RefreshCw className="w-3 h-3" />
                <span>Retry</span>
              </button>
            </div>
          )}

          {/* Rendered Explanation */}
          {!isLoading && explanation && (
            <div className="space-y-4 text-xs">
              {/* Meaning & Security Rationale */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                <div className="p-3 rounded-lg bg-white border border-slate-200/80 space-y-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-slate-500 block">
                    What This Finding Means
                  </span>
                  <p className="text-slate-700 leading-relaxed">{explanation.meaning}</p>
                </div>

                <div className="p-3 rounded-lg bg-white border border-slate-200/80 space-y-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-slate-500 block">
                    Why It Matters
                  </span>
                  <p className="text-slate-700 leading-relaxed">{explanation.why_it_matters}</p>
                </div>
              </div>

              {/* Quantum Threat & Component Details */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                <div className="p-3 rounded-lg bg-indigo-50/50 border border-indigo-100 space-y-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-[#5755D9] block">
                    Quantum Threat Model (Shor / Grover)
                  </span>
                  <p className="text-slate-800 leading-relaxed">{explanation.quantum_relevance}</p>
                </div>

                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200/80 space-y-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-slate-500 block">
                    Cryptographic Role & Component
                  </span>
                  <p className="text-slate-700 leading-relaxed">{explanation.crypto_component}</p>
                </div>
              </div>

              {/* Evidence Grounding: Observed vs Not Observable */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                <div className="p-3 rounded-lg bg-emerald-50/40 border border-emerald-200/70 space-y-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-emerald-800 block">
                    What Verified Evidence Confirms
                  </span>
                  <p className="text-slate-700 leading-relaxed">{explanation.what_evidence_establishes}</p>
                </div>

                <div className="p-3 rounded-lg bg-amber-50/40 border border-amber-200/70 space-y-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-amber-800 block">
                    What Evidence Does NOT Establish (Invariant)
                  </span>
                  <p className="text-slate-700 leading-relaxed">{explanation.what_evidence_does_not_establish}</p>
                </div>
              </div>

              {/* Banking Impact & Remediation Guidance */}
              <div className="p-3.5 rounded-lg bg-white border border-slate-200/80 space-y-2">
                <div className="space-y-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-rose-800 block">
                    Potential Banking Infrastructure Impact
                  </span>
                  <p className="text-slate-700 leading-relaxed">{explanation.banking_impact}</p>
                </div>

                <div className="pt-2 border-t border-slate-100 space-y-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-[#5755D9] block">
                    Prescriptive Remediation & Standards Path
                  </span>
                  <p className="text-slate-800 leading-relaxed font-medium">{explanation.remediation}</p>
                </div>

                <div className="pt-2 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between text-[11px] text-slate-500 gap-1 font-mono">
                  <span>Standards: {explanation.standards_guidance}</span>
                  <button
                    type="button"
                    onClick={fetchExplanation}
                    className="text-[#5755D9] hover:underline cursor-pointer flex items-center space-x-1"
                  >
                    <RefreshCw className="w-2.5 h-2.5" />
                    <span>Re-evaluate</span>
                  </button>
                </div>
              </div>

              {/* Advisory Disclaimer */}
              <div className="text-[10px] font-mono text-slate-400 text-center pt-1">
                {explanation.advisory_disclaimer}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

