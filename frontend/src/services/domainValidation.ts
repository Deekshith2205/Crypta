/**
 * Client-side domain, port, and file upload validation.
 * Conforms strictly to RFC 1035/1123, SSRF protections, and QuantumShield backend constraints.
 */

export interface DomainValidationResult {
  isValid: boolean;
  normalized: string;
  error?: string;
  warning?: string;
}

export interface PortValidationResult {
  isValid: boolean;
  port: number;
  error?: string;
}

export interface UploadValidationResult {
  isValid: boolean;
  error?: string;
}

// RFC 1035/1123 regex for individual domain labels
export const LABEL_REGEX = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;

// Valid TLD pattern (at least 2 alphabetic chars or internationalized punycode xn--)
export const TLD_REGEX = /^(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9]+)$/;

export const PROHIBITED_TLDS = [
  '.local',
  '.internal',
  '.lan',
  '.corp',
  '.home',
  '.test',
  '.onion',
  '.invalid',
  '.example',
  '.arpa',
  '.intranet',
  '.localhost',
] as const;

export const PROHIBITED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'broadcasthost',
]);

export const MAX_UPLOAD_FILE_SIZE = 1024 * 1024; // 1 MiB
export const MAX_UPLOAD_TOTAL_SIZE = 5 * 1024 * 1024; // 5 MiB
export const MAX_UPLOAD_FILES = 20;

/**
 * Checks if a string is an IPv4 literal.
 */
function isIPv4(candidate: string): boolean {
  const parts = candidate.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    return n >= 0 && n <= 255 && (p === '0' || !p.startsWith('0'));
  });
}

/**
 * Checks if a string is an IPv6 literal (basic structure check).
 */
function isIPv6(candidate: string): boolean {
  const unbracketed = candidate.startsWith('[') && candidate.endsWith(']')
    ? candidate.slice(1, -1)
    : candidate;
  if (!unbracketed.includes(':')) return false;
  return /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/.test(unbracketed);
}

/**
 * Validates and normalizes domain input against RFC 1035/1123 and backend SSRF rules.
 */
export function validateDomain(input: string): DomainValidationResult {
  if (!input || typeof input !== 'string') {
    return {
      isValid: false,
      normalized: '',
      error: 'Domain input cannot be empty.',
    };
  }

  const cleaned = input.trim();
  if (!cleaned) {
    return {
      isValid: false,
      normalized: '',
      error: 'Domain input cannot be empty.',
    };
  }

  if (cleaned.length > 253) {
    return {
      isValid: false,
      normalized: '',
      error: 'Domain name exceeds maximum length of 253 characters (RFC 1035).',
    };
  }

  if (/\s/.test(cleaned)) {
    return {
      isValid: false,
      normalized: '',
      error: 'Invalid domain name format: domain name cannot contain whitespace.',
    };
  }

  // Reject URL schemes
  if (cleaned.includes('://') || /^(http|https|ftp|ws|wss):/i.test(cleaned)) {
    return {
      isValid: false,
      normalized: '',
      error: "Invalid input format: URL schemes ('http://' or 'https://') are not allowed. Please enter only a domain name (e.g. example.com).",
    };
  }

  // Reject URL paths
  if (cleaned.includes('/') || cleaned.includes('\\')) {
    return {
      isValid: false,
      normalized: '',
      error: 'Invalid input format: URL paths are not allowed. Please enter only a domain name (e.g. example.com).',
    };
  }

  // Reject query parameters and fragments
  if (cleaned.includes('?') || cleaned.includes('#')) {
    return {
      isValid: false,
      normalized: '',
      error: 'Invalid input format: Query parameters and URL fragments are not allowed.',
    };
  }

  // Reject credentials
  if (cleaned.includes('@')) {
    return {
      isValid: false,
      normalized: '',
      error: 'Invalid input format: User credentials are not permitted in domain names.',
    };
  }

  // Reject direct IP literals
  const strippedBrackets = cleaned.startsWith('[') && cleaned.endsWith(']') ? cleaned.slice(1, -1) : cleaned;
  if (isIPv4(strippedBrackets) || isIPv6(strippedBrackets)) {
    return {
      isValid: false,
      normalized: '',
      error: `Direct IP addresses are prohibited (${cleaned}). Please enter a valid Fully Qualified Domain Name (e.g. example.com).`,
    };
  }

  // Reject inline ports
  if (cleaned.includes(':')) {
    return {
      isValid: false,
      normalized: '',
      error: 'Invalid input format: Port numbers cannot be included in domain name. Use the dedicated port parameter if needed.',
    };
  }

  const fqdn = cleaned.toLowerCase().replace(/\.+$/, '');

  // Reject prohibited hostnames
  if (PROHIBITED_HOSTNAMES.has(fqdn)) {
    return {
      isValid: false,
      normalized: '',
      error: `Scanning internal or local domains (${cleaned}) is strictly prohibited.`,
    };
  }

  // Reject prohibited TLDs
  for (const prohibitedTld of PROHIBITED_TLDS) {
    if (fqdn.endsWith(prohibitedTld)) {
      return {
        isValid: false,
        normalized: '',
        error: `Scanning internal or local domains (${cleaned}) is strictly prohibited.`,
      };
    }
  }

  // Must be multi-label
  const labels = fqdn.split('.');
  if (labels.length < 2) {
    return {
      isValid: false,
      normalized: '',
      error: `Scanning internal or local domains (${cleaned}) is strictly prohibited. Must be a valid Fully Qualified Domain Name (e.g. example.com).`,
    };
  }

  // Validate each label
  for (const label of labels) {
    if (!label) {
      return {
        isValid: false,
        normalized: '',
        error: `Invalid domain name format: '${cleaned}' contains consecutive dots.`,
      };
    }
    if (label.length > 63) {
      return {
        isValid: false,
        normalized: '',
        error: `Domain label '${label}' exceeds maximum length of 63 characters.`,
      };
    }
    if (!LABEL_REGEX.test(label)) {
      return {
        isValid: false,
        normalized: '',
        error: `Invalid domain name format: label '${label}' contains invalid characters. Must contain only alphanumeric characters and hyphens, and cannot start or end with a hyphen.`,
      };
    }
  }

  // Validate TLD
  const tld = labels[labels.length - 1];
  if (!TLD_REGEX.test(tld)) {
    return {
      isValid: false,
      normalized: '',
      error: `Invalid top-level domain '${tld}'. TLD must be alphabetic and at least 2 characters.`,
    };
  }

  return {
    isValid: true,
    normalized: fqdn,
  };
}

/**
 * Validates network port (bounds 1 - 65535, default 443).
 */
export function validatePort(port: number | string | undefined): PortValidationResult {
  if (port === undefined || port === null || port === '') {
    return { isValid: true, port: 443 };
  }

  const num = typeof port === 'number' ? port : Number(port);
  if (!Number.isInteger(num)) {
    return {
      isValid: false,
      port: 443,
      error: 'Port must be a valid integer.',
    };
  }

  if (num < 1 || num > 65535) {
    return {
      isValid: false,
      port: 443,
      error: 'Port must be between 1 and 65535.',
    };
  }

  return {
    isValid: true,
    port: num,
  };
}

/**
 * Validates uploaded files against size and count limits.
 */
export function validateUploadFiles(
  files: Array<{ name: string; size: number }>,
  mode: 'config' | 'code' | 'certificate' = 'config'
): UploadValidationResult {
  if (!files || files.length === 0) {
    return {
      isValid: false,
      error: mode === 'certificate' ? 'Please select a certificate file.' : 'Please select at least one file to upload.',
    };
  }

  if (mode === 'certificate' && files.length > 1) {
    return {
      isValid: false,
      error: 'Certificate scan accepts exactly one file at a time.',
    };
  }

  if (files.length > MAX_UPLOAD_FILES) {
    return {
      isValid: false,
      error: `Select between 1 and ${MAX_UPLOAD_FILES} files.`,
    };
  }

  const oversizedFile = files.find((f) => f.size > MAX_UPLOAD_FILE_SIZE);
  if (oversizedFile) {
    return {
      isValid: false,
      error: `File "${oversizedFile.name}" exceeds maximum allowed size of 1 MiB.`,
    };
  }

  const totalSize = files.reduce((acc, f) => acc + f.size, 0);
  if (totalSize > MAX_UPLOAD_TOTAL_SIZE) {
    return {
      isValid: false,
      error: 'Combined file size must not exceed 5 MiB.',
    };
  }

  return { isValid: true };
}
