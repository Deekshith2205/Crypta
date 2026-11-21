import React, { useState, useEffect } from 'react';
import { Sparkles } from 'lucide-react';
import { getAIStatus } from '../../services/api';
import type { AIStatus } from '../../types/scan';

export const AIStatusBadge: React.FC = () => {
  const [status, setStatus] = useState<AIStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    let mounted = true;
    getAIStatus()
      .then((data) => {
        if (mounted) {
          setStatus(data);
          setLoading(false);
        }
      })
      .catch(() => {
        if (mounted) {
          setStatus({
            is_available: false,
            provider: 'none',
            message: 'AI provider is offline or unconfigured.',
          });
          setLoading(false);
        }
      });
    return () => {
      mounted = false;
    };
  }, []);

  if (loading) {
    return (
      <div className="hidden sm:inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-100 text-slate-500 text-[11px] font-mono border border-slate-200">
        <span className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-pulse" />
        <span>AI Checking...</span>
      </div>
    );
  }

  if (status?.is_available) {
    return (
      <div
        className="hidden sm:inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-indigo-50 text-[#5755D9] text-[11px] font-mono border border-indigo-200 shadow-2xs"
        title={`AI Advisory Active: ${status.provider} (${status.model || 'default'})`}
      >
        <Sparkles className="w-3 h-3 text-[#5755D9]" />
        <span className="font-semibold uppercase tracking-wider">AI Ready</span>
        <span className="text-slate-400">·</span>
        <span className="text-slate-600 capitalize">{status.provider}</span>
      </div>
    );
  }

  return (
    <div
      className="hidden sm:inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-100 text-slate-500 text-[11px] font-mono border border-slate-200"
      title="AI Intelligence is optional. Configure GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY to enable."
    >
      <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
      <span>AI: Optional</span>
    </div>
  );
};

