import type {
  ScanResponse,
  BankingSystemProfile,
  BankingRiskAssessment,
  RankedUpgradePlan,
  WhatIfMigrationRequest,
  WhatIfMigrationResult,
  AuditRecord,
  AuditVerificationResult,
  AuditLedgerResponse,
  AuditHeadResponse,
  CompleteAssessmentReport,
  ArtifactFindingsResponse,
  UploadedCertificateResponse,
  AIStatus,
  AIExplanationResult,
  FindingExplanationRequest,
  FindingExplanationResponse,
  BankingRiskExplanationRequest,
  BankingRiskExplanationResponse,
  MigrationAdvisoryRequest,
  MigrationAdvisoryResponse,
  ReportExplanationRequest,
  ReportExplanationResponse,
  AIBudgetTelemetry,
} from '../types/scan.ts';
import { validateUploadFiles } from './domainValidation.ts';

const API_BASE = (
  typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_URL
    ? import.meta.env.VITE_API_URL
    : ''
).replace(/\/+$/, '');

export const DEFAULT_TIMEOUT_MS = 15000;
export const DIRECT_BACKEND_ORIGIN = 'http://127.0.0.1:8000';

/**
 * Builds a resolved URL given a path and optional base.
 */
export function buildResolvedUrl(path: string, base: string = API_BASE): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  if (!base) return normalizedPath;
  return `${base.replace(/\/+$/, '')}${normalizedPath}`;
}

/**
 * Extracts a human-readable error message from an error response or payload.
 */
export function extractApiErrorMessage(errorData: unknown, httpStatus?: number): string {
  if (errorData && typeof errorData === 'object') {
    const err = errorData as Record<string, unknown>;
    if (typeof err.detail === 'string' && err.detail.trim()) {
      return err.detail.trim();
    }
    if (typeof err.error === 'string' && err.error.trim()) {
      return err.error.trim();
    }
    if (typeof err.message === 'string' && err.message.trim()) {
      return err.message.trim();
    }
  }
  return httpStatus ? `Request failed with HTTP ${httpStatus}` : 'An unexpected error occurred.';
}

/**
 * Executes a network fetch with configurable timeout (15s default) and automatic
 * dual-try fallback to direct backend origin (http://127.0.0.1:8000).
 */
export async function fetchWithFallback<T>(
  path: string,
  options: RequestInit = {},
  fallbackMessage?: string
): Promise<T> {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const primaryUrl = buildResolvedUrl(normalizedPath, API_BASE);
  const secondaryUrl = `${DIRECT_BACKEND_ORIGIN}${normalizedPath}`;

  const executeFetch = async (targetUrl: string): Promise<Response> => {
    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    let signal = options.signal;

    if (!signal) {
      if (typeof AbortSignal !== 'undefined' && 'timeout' in AbortSignal) {
        signal = AbortSignal.timeout(DEFAULT_TIMEOUT_MS);
      } else if (typeof AbortController !== 'undefined') {
        const controller = new AbortController();
        timeoutId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
        signal = controller.signal;
      }
    }

    try {
      return await fetch(targetUrl, { ...options, signal });
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
    }
  };

  let response: Response;
  try {
    response = await executeFetch(primaryUrl);
  } catch {
    // If primary failed and is distinct from secondary, attempt fallback
    if (primaryUrl !== secondaryUrl) {
      try {
        response = await executeFetch(secondaryUrl);
      } catch {
        throw new Error(
          fallbackMessage ||
            `Unable to connect to QuantumShield backend at ${secondaryUrl}. Please verify backend service is running.`
        );
      }
    } else {
      throw new Error(
        fallbackMessage ||
          'Unable to connect to QuantumShield backend. Please verify backend service is running.'
      );
    }
  }

  if (!response.ok) {
    let errorData: unknown;
    try {
      errorData = await response.json();
    } catch {
      // Non-JSON response body
    }
    const message = extractApiErrorMessage(errorData, response.status);
    throw new Error(message);
  }

  return response.json();
}

/**
 * Specialized fetch for binary downloads (PDF reports) with fallback and timeout.
 */
export async function fetchBlobWithFallback(
  path: string,
  options: RequestInit = {},
  fallbackMessage?: string
): Promise<Blob> {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const primaryUrl = buildResolvedUrl(normalizedPath, API_BASE);
  const secondaryUrl = `${DIRECT_BACKEND_ORIGIN}${normalizedPath}`;

  const executeFetch = async (targetUrl: string): Promise<Response> => {
    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    let signal = options.signal;

    if (!signal) {
      if (typeof AbortSignal !== 'undefined' && 'timeout' in AbortSignal) {
        signal = AbortSignal.timeout(DEFAULT_TIMEOUT_MS);
      } else if (typeof AbortController !== 'undefined') {
        const controller = new AbortController();
        timeoutId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
        signal = controller.signal;
      }
    }

    try {
      return await fetch(targetUrl, { ...options, signal });
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
    }
  };

  let response: Response;
  try {
    response = await executeFetch(primaryUrl);
  } catch {
    if (primaryUrl !== secondaryUrl) {
      try {
        response = await executeFetch(secondaryUrl);
      } catch {
        throw new Error(fallbackMessage || 'Unable to connect to report download service.');
      }
    } else {
      throw new Error(fallbackMessage || 'Unable to connect to report download service.');
    }
  }

  if (!response.ok) {
    let errorData: unknown;
    try {
      errorData = await response.json();
    } catch {
      // Non-JSON response body
    }
    const message = extractApiErrorMessage(errorData, response.status);
    throw new Error(message);
  }

  return response.blob();
}

// ==============================================================================
// SCAN & ASSESSMENT ENDPOINTS
// ==============================================================================

export async function scanDomain(
  domain: string,
  port: number = 443,
  probe_pqc: boolean = false,
  asset_id?: string
): Promise<ScanResponse> {
  const payload = { domain, port, probe_pqc, ...(asset_id ? { asset_id } : {}) };
  return fetchWithFallback<ScanResponse>(
    '/api/scan',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    },
    'Unable to connect to QuantumShield assessment backend. Please verify backend is running.'
  );
}

// ==============================================================================
// BANKING PROFILE & RISK ENDPOINTS
// ==============================================================================

export async function getBankingProfiles(): Promise<BankingSystemProfile[]> {
  return fetchWithFallback<BankingSystemProfile[]>(
    '/api/banking/profiles',
    { method: 'GET' },
    'Unable to fetch banking profiles from backend.'
  );
}

export async function getBankingProfileById(id: string): Promise<BankingSystemProfile> {
  return fetchWithFallback<BankingSystemProfile>(
    `/api/banking/profiles/${encodeURIComponent(id)}`,
    { method: 'GET' },
    `Unable to fetch banking profile "${id}" from backend.`
  );
}

export async function getBankingRiskRankings(): Promise<BankingRiskAssessment[]> {
  return fetchWithFallback<BankingRiskAssessment[]>(
    '/api/banking/risk',
    { method: 'GET' },
    'Unable to fetch banking risk rankings from backend.'
  );
}

export async function getBankingUpgradePlan(): Promise<RankedUpgradePlan> {
  return fetchWithFallback<RankedUpgradePlan>(
    '/api/banking/upgrade-plan',
    { method: 'GET' },
    'Unable to fetch banking upgrade plan from backend.'
  );
}

export async function getBankingProfileRisk(id: string): Promise<BankingRiskAssessment> {
  return fetchWithFallback<BankingRiskAssessment>(
    `/api/banking/profiles/${encodeURIComponent(id)}/risk`,
    { method: 'GET' },
    `Unable to fetch risk assessment for profile "${id}".`
  );
}

export async function simulateMigration(
  request: WhatIfMigrationRequest
): Promise<WhatIfMigrationResult> {
  return fetchWithFallback<WhatIfMigrationResult>(
    '/api/banking/risk/what-if',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    },
    'Unable to connect to QuantumShield migration simulation service.'
  );
}

export async function checkBackendHealth(): Promise<boolean> {
  try {
    const res = await fetch(buildResolvedUrl('/api/health', API_BASE));
    if (res.ok) return true;
  } catch {
    try {
      const res2 = await fetch(`${DIRECT_BACKEND_ORIGIN}/api/health`);
      return res2.ok;
    } catch {
      return false;
    }
  }
  return false;
}

// ==============================================================================
// REPORT DOWNLOADS & AUDIT VERIFICATION
// ==============================================================================

export async function getBankingSystemJsonReport(
  systemId: string
): Promise<CompleteAssessmentReport> {
  return fetchWithFallback<CompleteAssessmentReport>(
    `/api/banking/systems/${encodeURIComponent(systemId)}/report/json?include_ai=true`,
    { method: 'GET' },
    'Unable to connect to the report service.'
  );
}

export async function getBankingSystemPdfReport(
  systemId: string
): Promise<Blob> {
  return fetchBlobWithFallback(
    `/api/banking/systems/${encodeURIComponent(systemId)}/report/pdf?include_ai=true`,
    { method: 'GET' },
    'Unable to connect to the PDF report service.'
  );
}

export async function verifyAuditRecord(
  record: AuditRecord
): Promise<AuditVerificationResult> {
  return fetchWithFallback<AuditVerificationResult>(
    '/api/audit/verify',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ record }),
    },
    'Unable to connect to the audit verification service.'
  );
}

export async function getAuditLedger(
  limit: number = 50,
  offset: number = 0,
  systemId?: string
): Promise<AuditLedgerResponse> {
  const query = new URLSearchParams({
    limit: limit.toString(),
    offset: offset.toString(),
  });
  if (systemId) {
    query.append('system_id', systemId);
  }
  return fetchWithFallback<AuditLedgerResponse>(
    `/api/audit/ledger?${query.toString()}`,
    { method: 'GET' },
    'Unable to connect to the audit ledger service.'
  );
}

export async function getAuditHead(): Promise<AuditHeadResponse> {
  return fetchWithFallback<AuditHeadResponse>(
    '/api/audit/head',
    { method: 'GET' },
    'Unable to connect to the audit head service.'
  );
}

// ==============================================================================
// UPLOADED ARTIFACT SCANNING
// ==============================================================================

async function readUploadFiles(
  files: File[],
  mode: 'config' | 'code' | 'certificate' = 'config'
): Promise<{ name: string; content: string }[]> {
  const validation = validateUploadFiles(files, mode);
  if (!validation.isValid) {
    throw new Error(validation.error || 'Upload validation failed.');
  }

  try {
    return await Promise.all(
      files.map(async (file) => ({
        name: file.name,
        content: await file.text(),
      }))
    );
  } catch {
    throw new Error('Unable to read the selected files.');
  }
}

export async function scanUploadedConfig(
  files: File[]
): Promise<ArtifactFindingsResponse> {
  const uploadedFiles = await readUploadFiles(files, 'config');
  return fetchWithFallback<ArtifactFindingsResponse>(
    '/api/scan/config',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ files: uploadedFiles }),
    },
    'Unable to connect to the Configuration scan service.'
  );
}

export async function scanUploadedCode(
  files: File[]
): Promise<ArtifactFindingsResponse> {
  const uploadedFiles = await readUploadFiles(files, 'code');
  return fetchWithFallback<ArtifactFindingsResponse>(
    '/api/scan/code',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ files: uploadedFiles }),
    },
    'Unable to connect to the Source-code scan service.'
  );
}

export async function scanUploadedCertificate(
  file: File
): Promise<UploadedCertificateResponse> {
  const uploadedFiles = await readUploadFiles([file], 'certificate');
  return fetchWithFallback<UploadedCertificateResponse>(
    '/api/scan/cert',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(uploadedFiles[0]),
    },
    'Unable to connect to the Certificate scan service.'
  );
}

// ==============================================================================
// AI READINESS INTELLIGENCE & TELEMETRY
// ==============================================================================

export async function getAIStatus(): Promise<AIStatus> {
  try {
    return await fetchWithFallback<AIStatus>(
      '/api/ai/status',
      { method: 'GET' },
      'AI service status unavailable.'
    );
  } catch (err: unknown) {
    return {
      is_available: false,
      provider: 'none',
      message: err instanceof Error ? err.message : 'Unable to connect to QuantumShield AI service.',
    };
  }
}

export async function getAIBudget(): Promise<AIBudgetTelemetry> {
  return fetchWithFallback<AIBudgetTelemetry>(
    '/api/ai/budget',
    { method: 'GET' },
    'Unable to fetch AI budget and rate-limit telemetry from backend.'
  );
}

export async function explainFinding(
  payload: FindingExplanationRequest
): Promise<AIExplanationResult<FindingExplanationResponse>> {
  return fetchWithFallback<AIExplanationResult<FindingExplanationResponse>>(
    '/api/ai/explain/finding',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    },
    'Failed to contact AI service for finding explanation.'
  );
}

export async function explainBankingRisk(
  payload: BankingRiskExplanationRequest
): Promise<AIExplanationResult<BankingRiskExplanationResponse>> {
  return fetchWithFallback<AIExplanationResult<BankingRiskExplanationResponse>>(
    '/api/ai/explain/banking-risk',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    },
    'Failed to contact AI service for banking risk explanation.'
  );
}

export async function adviseMigration(
  payload: MigrationAdvisoryRequest
): Promise<AIExplanationResult<MigrationAdvisoryResponse>> {
  return fetchWithFallback<AIExplanationResult<MigrationAdvisoryResponse>>(
    '/api/ai/advisory/migration',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    },
    'Failed to contact AI service for migration advisory.'
  );
}

export async function explainReport(
  payload: ReportExplanationRequest
): Promise<AIExplanationResult<ReportExplanationResponse>> {
  return fetchWithFallback<AIExplanationResult<ReportExplanationResponse>>(
    '/api/ai/explain/report',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    },
    'Failed to contact AI service for report explanation.'
  );
}
