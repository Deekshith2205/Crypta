import type {
  QuantumFinding,
  FindingExplanationRequest,
  FindingExplanationResponse,
  AIExplanationResult,
} from '../../types/scan';

/**
 * Classifies the AI explanation's risk domain using the scanner's
 * structured threat vector rather than the descriptive threat text.
 *
 * QUANTUM identifies the assessment domain, not a vulnerability verdict.
 * Evidence status and scanner severity remain independent and authoritative.
 */
export const getRiskDomain = (vector: string | undefined | null): string => {
  const normalized = vector?.trim().toUpperCase();

  switch (normalized) {
    case 'SHOR':
    case 'GROVER':
    case 'SNDL':
    case 'CLASSICAL_BROKEN':
    case 'RESISTANT':
    case 'POST_QUANTUM':
      return 'QUANTUM';

    default:
      return 'NOT_OBSERVABLE';
  }
};

/**
 * Builds the canonical FindingExplanationRequest payload from a QuantumFinding.
 * Applies structured fallbacks for role, source, value, evidence_status, and risk domain.
 */
export const buildFindingExplanationRequest = (
  finding: QuantumFinding
): FindingExplanationRequest => ({
  rule_id: finding.id,
  title: finding.title,
  value: finding.value || finding.algorithm || 'Declared Cryptography',

  role:
    finding.role ||
    (finding.category === 'public_key'
      ? 'DIGITAL_SIGNATURE'
      : finding.category === 'key_exchange'
        ? 'KEY_EXCHANGE'
        : 'DATA_ENCRYPTION'),

  source: finding.source || finding.observed_from || 'EXTERNAL_SCAN',

  evidence_status: (
    finding.evidence?.trim() ||
    finding.observability?.trim() ||
    'NOT_OBSERVABLE'
  ).toUpperCase(),

  severity: finding.risk_level || 'MEDIUM',

  risk: getRiskDomain(finding.quantum_threat_vector),

  message: finding.security_impact || finding.reason,

  recommendation: finding.recommendation,
});

export interface ValidationOutcome {
  data: FindingExplanationResponse | null;
  error: string | null;
  unavailable: boolean;
}

/**
 * Validates the AI explanation response against the active request identity.
 * Rejects mismatched rule_id responses to prevent stale or cross-finding display.
 */
export const validateExplanationResponse = (
  requestRuleId: string,
  result: AIExplanationResult<FindingExplanationResponse>
): ValidationOutcome => {
  if (result.success && result.data) {
    if (result.data.rule_id !== requestRuleId) {
      return {
        data: null,
        error: 'The AI service returned an explanation for a different finding.',
        unavailable: false,
      };
    }
    return { data: result.data, error: null, unavailable: false };
  }

  if (!result.is_available) {
    return {
      data: null,
      error:
        result.error ||
        'AI provider is not configured. Configure GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY to enable.',
      unavailable: true,
    };
  }

  return {
    data: null,
    error: result.error || 'Unable to generate AI explanation.',
    unavailable: false,
  };
};

/**
 * Helper to determine whether an asynchronous response should be accepted
 * based on request generation tracking and request identity matching.
 */
export const shouldAcceptResponse = (
  currentGeneration: number,
  responseGeneration: number,
  currentIdentity: string,
  responseIdentity: string
): boolean => {
  return (
    currentGeneration === responseGeneration &&
    currentIdentity === responseIdentity
  );
};

