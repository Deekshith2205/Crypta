import { test, describe } from 'node:test';
import assert from 'node:assert';
import {
  validateDomain,
  validatePort,
  validateUploadFiles,
  MAX_UPLOAD_FILES,
  MAX_UPLOAD_FILE_SIZE,
} from './domainValidation.ts';

describe('Domain Validation - 1. Valid RFC 1035/1123 Domains', () => {
  test('accepts standard multi-label domains and normalizes them', () => {
    const validCases = [
      { input: 'example.com', expected: 'example.com' },
      { input: 'EXAMPLE.COM', expected: 'example.com' },
      { input: 'subdomain.bank.com.', expected: 'subdomain.bank.com' },
      { input: '  portal.secure-banking.org  ', expected: 'portal.secure-banking.org' },
      { input: 'tls-v1-2.badssl.com', expected: 'tls-v1-2.badssl.com' },
      { input: 'api-v2.internal-cloud.io', expected: 'api-v2.internal-cloud.io' },
      { input: 'xn--e1afmkfd.xn--p1ai', expected: 'xn--e1afmkfd.xn--p1ai' },
    ];

    for (const { input, expected } of validCases) {
      const result = validateDomain(input);
      assert.strictEqual(result.isValid, true, `Expected valid for "${input}"`);
      assert.strictEqual(result.normalized, expected, `Expected normalized "${expected}" for "${input}"`);
      assert.strictEqual(result.error, undefined);
    }
  });

  test('enforces label character constraints (alphanumeric and hyphens, no trailing/leading hyphen)', () => {
    const validLabels = 'alpha-1.beta-2.gamma3.com';
    assert.strictEqual(validateDomain(validLabels).isValid, true);

    const leadingHyphen = '-alpha.bank.com';
    assert.strictEqual(validateDomain(leadingHyphen).isValid, false);

    const trailingHyphen = 'alpha-.bank.com';
    assert.strictEqual(validateDomain(trailingHyphen).isValid, false);

    const specialChars = 'bank$security.com';
    assert.strictEqual(validateDomain(specialChars).isValid, false);
  });
});

describe('Domain Validation - 2. Prohibited Schemes, Paths, and Credentials', () => {
  test('rejects URL schemes', () => {
    const schemeInputs = [
      'https://example.com',
      'http://bank.com',
      'ftp://files.bank.com',
      'ws://socket.bank.com',
      'wss://secure.bank.com',
      'custom://example.com',
    ];

    for (const input of schemeInputs) {
      const result = validateDomain(input);
      assert.strictEqual(result.isValid, false, `Scheme "${input}" should be rejected`);
      assert.match(result.error || '', /URL schemes/i);
    }
  });

  test('rejects URL paths, queries, and fragments', () => {
    const pathInputs = [
      'example.com/api',
      'example.com/',
      'example.com\\path',
      'bank.com/login?redirect=true',
      'bank.com?query=1',
      'bank.com#section',
    ];

    for (const input of pathInputs) {
      const result = validateDomain(input);
      assert.strictEqual(result.isValid, false, `Path/query "${input}" should be rejected`);
    }
  });

  test('rejects user credentials in domain names', () => {
    const credInputs = [
      'admin:secret@bank.com',
      'user@bank.com',
      '@bank.com',
    ];

    for (const input of credInputs) {
      const result = validateDomain(input);
      assert.strictEqual(result.isValid, false, `Credentials in "${input}" should be rejected`);
      assert.match(result.error || '', /credentials/i);
    }
  });

  test('rejects inline port specifications in domain names', () => {
    const portInputs = [
      'example.com:443',
      'bank.com:8443',
      'portal.bank.com:80',
    ];

    for (const input of portInputs) {
      const result = validateDomain(input);
      assert.strictEqual(result.isValid, false, `Inline port in "${input}" should be rejected`);
      assert.match(result.error || '', /port numbers cannot be included/i);
    }
  });
});

describe('Domain Validation - 3. IP Literals and Local Namespaces (SSRF Defense)', () => {
  test('rejects direct IPv4 literals', () => {
    const ip4Inputs = [
      '192.168.1.1',
      '127.0.0.1',
      '10.0.0.1',
      '172.16.0.1',
      '8.8.8.8',
      '0.0.0.0',
    ];

    for (const ip of ip4Inputs) {
      const result = validateDomain(ip);
      assert.strictEqual(result.isValid, false, `IPv4 "${ip}" should be rejected`);
      assert.match(result.error || '', /direct ip addresses are prohibited/i);
    }
  });

  test('rejects direct IPv6 literals', () => {
    const ip6Inputs = [
      '::1',
      '[::1]',
      '2001:db8::1',
      '[2001:db8::1]',
    ];

    for (const ip of ip6Inputs) {
      const result = validateDomain(ip);
      assert.strictEqual(result.isValid, false, `IPv6 "${ip}" should be rejected`);
    }
  });

  test('rejects prohibited local hostnames and internal TLDs', () => {
    const localInputs = [
      'localhost',
      'localhost.localdomain',
      'ip6-localhost',
      'broadcasthost',
      'bank.local',
      'service.internal',
      'core.lan',
      'vault.corp',
      'database.onion',
      'test.test',
      'sample.invalid',
      'router.home',
    ];

    for (const name of localInputs) {
      const result = validateDomain(name);
      assert.strictEqual(result.isValid, false, `Local domain "${name}" should be rejected`);
      assert.match(result.error || '', /strictly prohibited/i);
    }
  });

  test('rejects single-label domains', () => {
    const singleLabels = ['intranet', 'mainframe', 'corpgw', 'api'];

    for (const label of singleLabels) {
      const result = validateDomain(label);
      assert.strictEqual(result.isValid, false, `Single label "${label}" should be rejected`);
      assert.match(result.error || '', /strictly prohibited|fully qualified/i);
    }
  });
});

describe('Domain Validation - 4. Length and Formatting Boundaries', () => {
  test('rejects empty, null, or whitespace-only inputs', () => {
    const emptyInputs = ['', '   ', '\t\n'];

    for (const empty of emptyInputs) {
      const result = validateDomain(empty);
      assert.strictEqual(result.isValid, false);
      assert.match(result.error || '', /cannot be empty/i);
    }
  });

  test('rejects domain containing internal whitespace', () => {
    const whitespaceInput = 'example .com';
    const result = validateDomain(whitespaceInput);
    assert.strictEqual(result.isValid, false);
    assert.match(result.error || '', /cannot contain whitespace/i);
  });

  test('rejects domain exceeding RFC 1035 253 characters limit', () => {
    const longDomain = `${'a'.repeat(60)}.${'b'.repeat(60)}.${'c'.repeat(60)}.${'d'.repeat(60)}.${'e'.repeat(10)}.com`;
    assert.strictEqual(longDomain.length > 253, true);
    const result = validateDomain(longDomain);
    assert.strictEqual(result.isValid, false);
    assert.match(result.error || '', /exceeds maximum length of 253/i);
  });

  test('rejects domain label exceeding 63 characters', () => {
    const longLabel = `${'a'.repeat(64)}.bank.com`;
    const result = validateDomain(longLabel);
    assert.strictEqual(result.isValid, false);
    assert.match(result.error || '', /exceeds maximum length of 63/i);
  });

  test('rejects consecutive dots', () => {
    const consecutiveDots = 'bank..com';
    const result = validateDomain(consecutiveDots);
    assert.strictEqual(result.isValid, false);
    assert.match(result.error || '', /consecutive dots/i);
  });

  test('rejects invalid top-level domain format', () => {
    const singleCharTld = 'bank.c';
    assert.strictEqual(validateDomain(singleCharTld).isValid, false);

    const numericTld = 'bank.123';
    assert.strictEqual(validateDomain(numericTld).isValid, false);
  });
});

describe('Port Validation', () => {
  test('accepts valid TCP port numbers and defaults to 443', () => {
    assert.deepStrictEqual(validatePort(undefined), { isValid: true, port: 443 });
    assert.deepStrictEqual(validatePort(''), { isValid: true, port: 443 });
    assert.deepStrictEqual(validatePort(443), { isValid: true, port: 443 });
    assert.deepStrictEqual(validatePort('8443'), { isValid: true, port: 8443 });
    assert.deepStrictEqual(validatePort(1), { isValid: true, port: 1 });
    assert.deepStrictEqual(validatePort(65535), { isValid: true, port: 65535 });
  });

  test('rejects out of bounds and non-integer ports', () => {
    assert.strictEqual(validatePort(0).isValid, false);
    assert.strictEqual(validatePort(65536).isValid, false);
    assert.strictEqual(validatePort(-10).isValid, false);
    assert.strictEqual(validatePort('abc').isValid, false);
    assert.strictEqual(validatePort(443.5).isValid, false);
  });
});

describe('Upload Files Validation', () => {
  test('accepts valid file arrays within size and count constraints', () => {
    const validFiles = [
      { name: 'tls_config.json', size: 1024 },
      { name: 'openssl.cnf', size: 2048 },
    ];
    const result = validateUploadFiles(validFiles, 'config');
    assert.strictEqual(result.isValid, true);
    assert.strictEqual(result.error, undefined);
  });

  test('rejects empty file selection', () => {
    const result = validateUploadFiles([], 'config');
    assert.strictEqual(result.isValid, false);
    assert.match(result.error || '', /select at least one file/i);

    const certResult = validateUploadFiles([], 'certificate');
    assert.strictEqual(certResult.isValid, false);
    assert.match(certResult.error || '', /select a certificate file/i);
  });

  test('rejects multiple files in certificate mode', () => {
    const files = [
      { name: 'cert1.pem', size: 1024 },
      { name: 'cert2.pem', size: 1024 },
    ];
    const result = validateUploadFiles(files, 'certificate');
    assert.strictEqual(result.isValid, false);
    assert.match(result.error || '', /exactly one file/i);
  });

  test(`rejects more than ${MAX_UPLOAD_FILES} files`, () => {
    const files = Array.from({ length: 21 }, (_, i) => ({
      name: `file_${i}.txt`,
      size: 100,
    }));
    const result = validateUploadFiles(files, 'code');
    assert.strictEqual(result.isValid, false);
    assert.match(result.error || '', /between 1 and 20 files/i);
  });

  test('rejects single file exceeding 1 MiB', () => {
    const files = [{ name: 'huge_dump.sql', size: MAX_UPLOAD_FILE_SIZE + 1 }];
    const result = validateUploadFiles(files, 'config');
    assert.strictEqual(result.isValid, false);
    assert.match(result.error || '', /exceeds maximum allowed size of 1 MiB/i);
  });

  test('rejects total payload exceeding 5 MiB', () => {
    const files = [
      { name: 'file1.bin', size: MAX_UPLOAD_FILE_SIZE },
      { name: 'file2.bin', size: MAX_UPLOAD_FILE_SIZE },
      { name: 'file3.bin', size: MAX_UPLOAD_FILE_SIZE },
      { name: 'file4.bin', size: MAX_UPLOAD_FILE_SIZE },
      { name: 'file5.bin', size: MAX_UPLOAD_FILE_SIZE },
      { name: 'file6.bin', size: 1024 },
    ];
    const result = validateUploadFiles(files, 'config');
    assert.strictEqual(result.isValid, false);
    assert.match(result.error || '', /combined file size must not exceed 5 MiB/i);
  });
});
