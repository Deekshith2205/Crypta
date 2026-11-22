
import React, { useState } from 'react';
import { Search, Loader2, ArrowRight } from 'lucide-react';

interface DomainInputProps {
  onScan: (domain: string, port?: number, probePqc?: boolean, assetId?: string) => void;
  isLoading: boolean;
  currentDomain?: string;
  initialAssetId?: string;
}

export const DomainInput: React.FC<DomainInputProps> = ({
  onScan,
  isLoading,
  currentDomain = '',
  initialAssetId = '',
}) => {
  const [domain, setDomain] = useState(currentDomain);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (!domain.trim()) {
      setError('Please enter a valid domain name.');
      return;
    }

    setError(null);
    onScan(domain.trim(), 443, false, initialAssetId || undefined);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-3xl mx-auto space-y-4">
      <div className="flex items-center space-x-2 bg-white border border-slate-200 rounded-2xl p-2 shadow-xs focus-within:border-[#5755D9] focus-within:ring-1 focus-within:ring-[#5755D9] transition">
        <Search className="w-5 h-5 text-slate-400 ml-3" />

        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="Enter a domain to scan (e.g., example.com)"
          aria-label="Domain name to scan"
          className="flex-1 bg-transparent px-3 py-2 text-sm text-slate-900 placeholder-slate-400 focus:outline-none"
        />

        <button
          type="submit"
          disabled={isLoading}
          aria-label="Start domain cryptographic scan"
          className="inline-flex items-center space-x-2 px-6 py-2.5 rounded-xl bg-[#18181B] hover:bg-black text-white text-sm font-semibold transition cursor-pointer disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-[#5755D9] focus-visible:outline-none"
        >
          {isLoading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Scanning...</span>
            </>
          ) : (
            <>
              <span>Scan Now</span>
              <ArrowRight className="w-4 h-4" />
            </>
          )}
        </button>
      </div>

      {error && (
        <p role="alert" aria-live="polite" className="text-xs text-rose-600 pl-4">
          {error}
        </p>
      )}
    </form>
  );
};
