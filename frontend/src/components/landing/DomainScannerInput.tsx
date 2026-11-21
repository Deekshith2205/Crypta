import React, { useState } from 'react';
import {
  Globe,
  ArrowRight,
  Loader2,
  SlidersHorizontal,
  ChevronDown,
  ChevronUp,
  AlertCircle,
} from 'lucide-react';
import {
  EXAMPLE_DOMAINS,
  BANKING_PROFILES,
  getInlineDomainWarning,
  prepareScanPayload,
} from './domainScannerInputLogic.ts';

interface DomainScannerInputProps {
  onScan: (domain: string, port: number, probePqc?: boolean, assetId?: string) => void;
  isLoading: boolean;
  currentDomain?: string;
  initialAssetId?: string;
  className?: string;
}

export const DomainScannerInput: React.FC<DomainScannerInputProps> = ({
  onScan,
  isLoading,
  currentDomain = '',
  initialAssetId = '',
  className = '',
}) => {
  const [domain, setDomain] = useState(currentDomain);
  const [port, setPort] = useState(443);
  const [probePqc, setProbePqc] = useState(false);
  const [assetId, setAssetId] = useState(initialAssetId);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [previousInitialAssetId, setPreviousInitialAssetId] =
    useState(initialAssetId);
  const [previousCurrentDomain, setPreviousCurrentDomain] =
    useState(currentDomain);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Synchronize incoming profile changes without an effect.
  if (initialAssetId !== previousInitialAssetId) {
    setPreviousInitialAssetId(initialAssetId);
    if (initialAssetId) {
      setAssetId(initialAssetId);
    }
  }

  // Synchronize incoming domain changes without an effect.
  if (currentDomain !== previousCurrentDomain) {
    setPreviousCurrentDomain(currentDomain);
    if (currentDomain) {
      setDomain(currentDomain);
    }
  }

  const inlineWarning = getInlineDomainWarning(domain);

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setValidationError(null);

    const prepared = prepareScanPayload(domain, port, probePqc, assetId);
    if (!prepared.success) {
      setValidationError(prepared.error || 'Please enter a valid domain name.');
      return;
    }

    if (prepared.domain && !isLoading) {
      onScan(prepared.domain, prepared.port ?? 443, prepared.probePqc, prepared.assetId);
    }
  };

  const handleSelectExample = (
    exampleDomain: string,
    exampleAssetId?: string
  ) => {
    setValidationError(null);
    setDomain(exampleDomain);
    const chosenAsset = exampleAssetId || assetId;
    if (exampleAssetId) {
      setAssetId(exampleAssetId);
    }
    onScan(exampleDomain, 443, probePqc, chosenAsset || undefined);
  };

  return (
    <div className={`w-full max-w-[650px] space-y-3 ${className}`}>
      {/* Primary Input Container */}
      <form onSubmit={handleSubmit} className="relative w-full">
        <div className="flex items-center w-full h-[52px] bg-white rounded-[10px] border border-slate-200 shadow-[0_1px_4px_rgba(0,0,0,0.03)] focus-within:border-[#5755D9] focus-within:ring-2 focus-within:ring-[#5755D9]/10 transition-all pl-3.5 pr-1.5">
          {/* Globe Icon */}
          <div className="text-slate-400 shrink-0 mr-2.5">
            <Globe
              className="w-4 h-4 text-slate-400"
              strokeWidth={1.8}
            />
          </div>

          {/* Text Input */}
          <input
            id="domain-scanner-input"
            type="text"
            value={domain}
            onChange={(e) => {
              setDomain(e.target.value);
              if (validationError) setValidationError(null);
            }}
            placeholder="Enter a domain to scan (e.g., example.com)"
            disabled={isLoading}
            aria-label="Target domain name for cryptographic readiness scan"
            className="w-full bg-transparent text-[14.5px] text-[#0F172A] placeholder:text-slate-400 focus:outline-none py-2 font-normal focus-visible:ring-0"
          />

          {/* Scan Now Button */}
          <button
            type="submit"
            disabled={isLoading || !domain.trim()}
            aria-label="Start TLS post-quantum readiness scan"
            className="h-[40px] px-5 bg-[#18181B] hover:bg-black text-white text-[13.5px] font-medium rounded-[8px] flex items-center space-x-1.5 transition-all shadow-xs shrink-0 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed group focus-visible:ring-2 focus-visible:ring-[#5755D9] focus-visible:outline-none"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin text-white" />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <span>Scan Now</span>
                <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
              </>
            )}
          </button>
        </div>
      </form>

      {/* Validation or Inline Warning Notice */}
      {validationError && (
        <div className="flex items-center space-x-1.5 text-xs text-rose-600 bg-rose-50 border border-rose-200/80 px-3 py-2 rounded-lg font-mono">
          <AlertCircle className="w-3.5 h-3.5 shrink-0" />
          <span>{validationError}</span>
        </div>
      )}

      {!validationError && inlineWarning && (
        <div className="flex items-center space-x-1.5 text-[11.5px] text-amber-700 bg-amber-50/90 border border-amber-200/70 px-3 py-1.5 rounded-lg">
          <AlertCircle className="w-3.5 h-3.5 shrink-0 text-amber-600" />
          <span>{inlineWarning}</span>
        </div>
      )}

      {/* Example Domains Tag Pills */}
      <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
        <span className="text-[12.5px] text-slate-500 font-normal mr-1">
          Try examples:
        </span>

        {EXAMPLE_DOMAINS.map((item) => (
          <button
            key={item.domain}
            type="button"
            onClick={() => handleSelectExample(item.domain, item.assetId)}
            disabled={isLoading}
            aria-label={`Select example domain ${item.domain}`}
            className="text-[11.5px] font-normal px-2.5 py-0.5 rounded-full bg-[#F3F4F6] hover:bg-[#E5E7EB] text-[#4B5563] hover:text-[#0F172A] border border-slate-200/50 transition-colors cursor-pointer disabled:opacity-50 font-mono focus-visible:ring-2 focus-visible:ring-[#5755D9] focus-visible:outline-none"
          >
            {item.domain}
          </button>
        ))}

        {/* Subtle toggle for advanced audit parameters */}
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          aria-expanded={showAdvanced}
          aria-label={showAdvanced ? 'Hide advanced scan options' : 'Show advanced scan options'}
          className="ml-auto text-[11px] text-slate-400 hover:text-slate-600 transition flex items-center space-x-1 cursor-pointer font-mono focus-visible:ring-2 focus-visible:ring-[#5755D9] focus-visible:outline-none rounded px-1"
        >
          <SlidersHorizontal className="w-3 h-3" />
          <span>{showAdvanced ? 'Hide Options' : 'Options'}</span>
          {showAdvanced ? (
            <ChevronUp className="w-3 h-3" />
          ) : (
            <ChevronDown className="w-3 h-3" />
          )}
        </button>
      </div>

      {/* Collapsible Advanced Audit Options */}
      {showAdvanced && (
        <div className="p-3.5 rounded-xl bg-slate-50/90 border border-slate-200 text-xs space-y-2.5 animate-in fade-in duration-150">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
            <label htmlFor="banking-profile-select" className="text-[11.5px] font-medium text-slate-600">
              Banking Profile Context:
            </label>

            <select
              id="banking-profile-select"
              value={assetId}
              onChange={(e) => setAssetId(e.target.value)}
              disabled={isLoading}
              aria-label="Select banking profile context"
              className="w-full sm:w-auto px-2.5 py-1 rounded-lg bg-white border border-slate-300 text-slate-800 text-xs focus:outline-none cursor-pointer max-w-xs truncate focus-visible:ring-2 focus-visible:ring-[#5755D9]"
            >
              {BANKING_PROFILES.map((profile) => (
                <option key={profile.id} value={profile.id}>
                  {profile.label}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center justify-between pt-1 border-t border-slate-200/80">
            <label htmlFor="scan-port-input" className="text-[11.5px] font-medium text-slate-600">
              Target TCP Port (1-65535):
            </label>
            <input
              id="scan-port-input"
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(e) => setPort(Number(e.target.value) || 443)}
              disabled={isLoading}
              aria-label="Target port number"
              className="w-24 px-2 py-1 rounded-lg bg-white border border-slate-300 text-slate-800 text-xs focus:outline-none font-mono focus-visible:ring-2 focus-visible:ring-[#5755D9]"
            />
          </div>

          <div className="flex items-center justify-between pt-1 border-t border-slate-200/80">
            <label htmlFor="probe-pqc-checkbox" className="text-[11.5px] text-slate-600 cursor-pointer">
              Active Hybrid PQC Probe (ML-KEM):
            </label>

            <input
              id="probe-pqc-checkbox"
              type="checkbox"
              checked={probePqc}
              onChange={(e) => setProbePqc(e.target.checked)}
              disabled={isLoading}
              aria-label="Enable active hybrid post-quantum cryptography probe"
              className="rounded border-slate-300 text-[#5755D9] focus:ring-0 cursor-pointer w-4 h-4 focus-visible:ring-2 focus-visible:ring-[#5755D9]"
            />
          </div>
        </div>
      )}
    </div>
  );
};
