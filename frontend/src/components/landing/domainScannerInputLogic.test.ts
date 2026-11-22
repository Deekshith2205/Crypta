import { test, describe } from 'node:test';
import assert from 'node:assert';
import {
  getInlineDomainWarning,
  prepareScanPayload,
  EXAMPLE_DOMAINS,
  BANKING_PROFILES,
} from './domainScannerInputLogic.ts';

describe('Domain Scanner Input Logic - 1. Inline Feedback', () => {
  test('returns null for empty or valid domains', () => {
    assert.strictEqual(getInlineDomainWarning(''), null);
    assert.strictEqual(getInlineDomainWarning('   '), null);
    assert.strictEqual(getInlineDomainWarning('example.com'), null);
    assert.strictEqual(getInlineDomainWarning('bank.subdomain.org'), null);
  });

  test('detects URL scheme prefix', () => {
    const warningHttp = getInlineDomainWarning('http://bank.com');
    assert.ok(warningHttp);
    assert.match(warningHttp, /URL schemes/i);

    const warningHttps = getInlineDomainWarning('https://secure.bank.com');
    assert.ok(warningHttps);
    assert.match(warningHttps, /URL schemes/i);
  });

  test('detects URL path separator', () => {
    const warningPath = getInlineDomainWarning('bank.com/api');
    assert.ok(warningPath);
    assert.match(warningPath, /URL paths/i);
  });

  test('detects inline port notation', () => {
    const warningPort = getInlineDomainWarning('bank.com:443');
    assert.ok(warningPort);
    assert.match(warningPort, /Port numbers cannot be included/i);
  });

  test('detects direct IP pattern', () => {
    const warningIp = getInlineDomainWarning('10.0.0.1');
    assert.ok(warningIp);
    assert.match(warningIp, /Direct IP addresses are prohibited/i);
  });
});

describe('Domain Scanner Input Logic - 2. Scan Payload Preparation', () => {
  test('successfully prepares payload for valid domain and defaults port 443', () => {
    const result = prepareScanPayload('  EXAMPLE.COM.  ', undefined, true, 'BANK-PROF-NET-BANKING');
    assert.strictEqual(result.success, true);
    assert.strictEqual(result.domain, 'example.com');
    assert.strictEqual(result.port, 443);
    assert.strictEqual(result.probePqc, true);
    assert.strictEqual(result.assetId, 'BANK-PROF-NET-BANKING');
  });

  test('rejects malformed domains with descriptive error', () => {
    const result = prepareScanPayload('https://bank.com');
    assert.strictEqual(result.success, false);
    assert.match(result.error || '', /URL schemes/i);
  });

  test('rejects invalid ports with error', () => {
    const result = prepareScanPayload('bank.com', 99999);
    assert.strictEqual(result.success, false);
    assert.match(result.error || '', /between 1 and 65535/i);
  });

  test('handles example domains correctly', () => {
    assert.strictEqual(EXAMPLE_DOMAINS.length >= 4, true);
    for (const example of EXAMPLE_DOMAINS) {
      const prep = prepareScanPayload(example.domain, 443, false, example.assetId);
      assert.strictEqual(prep.success, true);
      assert.strictEqual(prep.domain, example.domain);
    }
  });

  test('banking profiles contain auto-infer option and defined profiles', () => {
    assert.strictEqual(BANKING_PROFILES[0].id, '');
    assert.strictEqual(BANKING_PROFILES.some((p) => p.id === 'BANK-PROF-CORE-BANKING'), true);
  });
});
