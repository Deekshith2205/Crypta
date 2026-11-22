import {
  validateDomain,
  validatePort,
} from '../../services/domainValidation.ts';

export interface ExampleDomainItem {
  domain: string;
  assetId: string;
}

export interface BankingProfileOption {
  id: string;
  label: string;
}

export const EXAMPLE_DOMAINS: ExampleDomainItem[] = [
  { domain: 'google.com', assetId: 'BANK-PROF-NET-BANKING' },
  { domain: 'python.org', assetId: 'BANK-PROF-CORE-BANKING' },
  { domain: 'cloudflare.com', assetId: 'BANK-PROF-PAYMENT-GATEWAY' },
  { domain: 'tls-v1-2.badssl.com', assetId: 'BANK-PROF-ATM-NETWORK' },
];

export const BANKING_PROFILES: BankingProfileOption[] = [
  { id: '', label: 'Auto-infer profile from target domain' },
  {
    id: 'BANK-PROF-PAYMENT-GATEWAY',
    label: 'Modern Payment Gateway (Critical / PQC Hybrid / HSM)',
  },
  {
    id: 'BANK-PROF-CORE-BANKING',
    label: 'Legacy Core Banking (Critical / RSA-2048 / Mainframe)',
  },
  {
    id: 'BANK-PROF-KYC-DB',
    label: 'Customer / KYC Database (Critical / Long SNDL / HSM)',
  },
  {
    id: 'BANK-PROF-NET-BANKING',
    label: 'Net Banking Portal (High / Web Banking / TLS 1.3)',
  },
  {
    id: 'BANK-PROF-ATM-NETWORK',
    label: 'ATM Network (High / 3DES / Dedicated Hardware)',
  },
];

/**
 * Returns a gentle non-blocking inline warning as the user types
 * before full form submission.
 */
export function getInlineDomainWarning(input: string): string | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  if (trimmed.toLowerCase().startsWith('http://') || trimmed.toLowerCase().startsWith('https://')) {
    return 'URL schemes (http://, https://) are not allowed. Enter the domain name only (e.g. example.com).';
  }

  if (trimmed.includes('/')) {
    return 'URL paths (/path) are not allowed. Enter the domain name only.';
  }

  if (trimmed.includes(':')) {
    return 'Port numbers cannot be included in the domain field. Use the Options toggle to set a custom port.';
  }

  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) {
    return 'Direct IP addresses are prohibited. Please specify a Fully Qualified Domain Name.';
  }

  return null;
}

export interface PreparedScanResult {
  success: boolean;
  domain?: string;
  port?: number;
  probePqc?: boolean;
  assetId?: string;
  error?: string;
}

/**
 * Prepares and validates parameters for domain scan dispatch.
 */
export function prepareScanPayload(
  domainInput: string,
  portInput: number | string = 443,
  probePqc: boolean = false,
  assetIdInput?: string
): PreparedScanResult {
  const domainValidation = validateDomain(domainInput);
  if (!domainValidation.isValid) {
    return {
      success: false,
      error: domainValidation.error || 'Invalid domain format.',
    };
  }

  const portValidation = validatePort(portInput);
  if (!portValidation.isValid) {
    return {
      success: false,
      error: portValidation.error || 'Invalid port specification.',
    };
  }

  return {
    success: true,
    domain: domainValidation.normalized,
    port: portValidation.port,
    probePqc,
    assetId: assetIdInput ? assetIdInput.trim() || undefined : undefined,
  };
}
