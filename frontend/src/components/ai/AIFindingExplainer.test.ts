import { test, describe } from 'node:test';
import assert from 'node:assert';
import {
  getRiskDomain,
  buildFindingExplanationRequest,
  validateExplanationResponse,
  shouldAcceptResponse,
} from './findingExplainerLogic.ts';
import type {
  QuantumFinding,
  FindingExplanationResponse,
  AIExplanationResult,
} from '../../types/scan.ts';

const createSampleFinding = (
  overrides: Partial<QuantumFinding> = {}
): QuantumFinding => ({
  id: 'FINDING-RSA-2048',
  title: 'RSA-2048 Asymmetric Key in Use',
  category: 'public_key',
  algorithm: 'RSA',
  role: 'DIGITAL_SIGNATURE',
  value: 'RSA-2048',
  source: 'TLS_CERTIFICATE',
  evidence: 'OBSERVED',
  observability: 'OBSERVED',
  risk_level: 'HIGH',
  quantum_threat: 'Shor algorithm vulnerability',
  quantum_threat_vector: 'SHOR',
  security_impact: 'Vulnerable to Shor polynomial-time factorization on CRQC.',
  reason: 'Vulnerable to Shor cryptanalysis',
  recommendation: 'Migrate to ML-DSA or stateful hash-based signatures.',
  migration_target: 'ML-DSA-65',
  priority: 'P1',
  priority_score: 85,
  observed_from: 'leaf_certificate',
  component: 'certificate_key',
  ...overrides,
});

const createSampleExplanationResponse = (
  ruleId = 'FINDING-RSA-2048'
): FindingExplanationResponse => ({
  rule_id: ruleId,
  meaning: 'RSA-2048 relies on the classical hardness of integer factorization.',
  why_it_matters: 'Store-now-decrypt-later and future Shor quantum attacks.',
  quantum_relevance: 'Shor algorithm breaks RSA-2048 completely.',
  crypto_component: 'Public Key Authentication',
  what_evidence_establishes: 'The certificate public key size is 2048 bits.',
  what_evidence_does_not_establish:
    'Does not indicate private key compromise today.',
  banking_impact: 'Potential fraud if transaction signatures are forged.',
  remediation: 'Transition to NIST FIPS 204 (ML-DSA).',
  migration_considerations: 'Ensure PKI and HSM support for hybrid certificates.',
  standards_guidance: 'NIST SP 800-208 / CNSA 2.0 timeline.',
  advisory_disclaimer:
    'AI Advisory — Informational Explanation Grounded in Verified Findings',
});

describe('AIFindingExplainer - 1. Threat Vector Mapping', () => {
  test('maps each supported threat vector to QUANTUM assessment domain', () => {
    const supportedVectors = [
      'SHOR',
      'GROVER',
      'SNDL',
      'CLASSICAL_BROKEN',
      'RESISTANT',
      'POST_QUANTUM',
    ];

    for (const vector of supportedVectors) {
      assert.strictEqual(
        getRiskDomain(vector),
        'QUANTUM',
        `Vector ${vector} should map to QUANTUM`
      );
      // Case-insensitivity and whitespace resilience
      assert.strictEqual(
        getRiskDomain(`  ${vector.toLowerCase()}  `),
        'QUANTUM',
        `Padded lowercase vector ${vector} should map to QUANTUM`
      );
    }
  });

  test('maps unknown and missing threat vectors to NOT_OBSERVABLE', () => {
    const unknownVectors = [
      undefined,
      null,
      '',
      '   ',
      'UNKNOWN',
      'RANDOM_VECTOR',
      'AES_256',
      'CUSTOM',
    ];

    for (const vector of unknownVectors) {
      assert.strictEqual(
        getRiskDomain(vector),
        'NOT_OBSERVABLE',
        `Vector ${String(vector)} should map to NOT_OBSERVABLE`
      );
    }
  });

  test('resistant findings map to QUANTUM assessment domain without altering severity or verdict', () => {
    const resistantFinding = createSampleFinding({
      id: 'FINDING-ML-KEM-768',
      title: 'ML-KEM-768 Hybrid Key Exchange Observed',
      quantum_threat_vector: 'RESISTANT',
      risk_level: 'LOW',
      evidence: 'OBSERVED',
      security_impact: 'Resilient against Shor algorithm attacks.',
      recommendation: 'Maintain hybrid configuration.',
    });

    const payload = buildFindingExplanationRequest(resistantFinding);

    // Domain is QUANTUM
    assert.strictEqual(payload.risk, 'QUANTUM');
    // Critical invariant: Severity remains authoritative and unchanged (LOW)
    assert.strictEqual(payload.severity, 'LOW');
    assert.strictEqual(payload.evidence_status, 'OBSERVED');
    assert.strictEqual(payload.rule_id, 'FINDING-ML-KEM-768');
  });
});

describe('AIFindingExplainer - 2. Request Payload Construction & Fallbacks', () => {
  test('constructs exact request payload from fully populated finding', () => {
    const finding = createSampleFinding();
    const payload = buildFindingExplanationRequest(finding);

    assert.strictEqual(payload.rule_id, 'FINDING-RSA-2048');
    assert.strictEqual(payload.title, 'RSA-2048 Asymmetric Key in Use');
    assert.strictEqual(payload.value, 'RSA-2048');
    assert.strictEqual(payload.role, 'DIGITAL_SIGNATURE');
    assert.strictEqual(payload.source, 'TLS_CERTIFICATE');
    assert.strictEqual(payload.evidence_status, 'OBSERVED');
    assert.strictEqual(payload.severity, 'HIGH');
    assert.strictEqual(payload.risk, 'QUANTUM');
    assert.strictEqual(
      payload.message,
      'Vulnerable to Shor polynomial-time factorization on CRQC.'
    );
    assert.strictEqual(
      payload.recommendation,
      'Migrate to ML-DSA or stateful hash-based signatures.'
    );
  });

  test('applies correct fallbacks when optional finding fields are missing', () => {
    const minimalFinding = createSampleFinding({
      id: 'FINDING-MINIMAL',
      title: 'Minimal Finding',
      category: 'key_exchange',
      algorithm: 'ECDH-P256',
      role: '',
      value: '',
      source: '',
      observed_from: '',
      evidence: '',
      observability: '',
      risk_level: 'MEDIUM',
      quantum_threat_vector: '',
      security_impact: '',
      reason: 'No detailed impact provided.',
      recommendation: 'Upgrade key agreement.',
    });

    const payload = buildFindingExplanationRequest(minimalFinding);

    assert.strictEqual(payload.rule_id, 'FINDING-MINIMAL');
    // value falls back to algorithm
    assert.strictEqual(payload.value, 'ECDH-P256');
    // role falls back based on category 'key_exchange'
    assert.strictEqual(payload.role, 'KEY_EXCHANGE');
    // source falls back to 'EXTERNAL_SCAN'
    assert.strictEqual(payload.source, 'EXTERNAL_SCAN');
    // evidence_status falls back to 'NOT_OBSERVABLE'
    assert.strictEqual(payload.evidence_status, 'NOT_OBSERVABLE');
    // severity falls back to 'MEDIUM'
    assert.strictEqual(payload.severity, 'MEDIUM');
    // risk falls back to 'NOT_OBSERVABLE'
    assert.strictEqual(payload.risk, 'NOT_OBSERVABLE');
    // message falls back to reason
    assert.strictEqual(payload.message, 'No detailed impact provided.');
  });

  test('role fallback respects category mappings correctly', () => {
    const pubKeyFinding = createSampleFinding({
      role: '',
      category: 'public_key',
    });
    assert.strictEqual(
      buildFindingExplanationRequest(pubKeyFinding).role,
      'DIGITAL_SIGNATURE'
    );

    const kexFinding = createSampleFinding({
      role: '',
      category: 'key_exchange',
    });
    assert.strictEqual(
      buildFindingExplanationRequest(kexFinding).role,
      'KEY_EXCHANGE'
    );

    const defaultFinding = createSampleFinding({
      role: '',
      category: 'symmetric_cipher',
    });
    assert.strictEqual(
      buildFindingExplanationRequest(defaultFinding).role,
      'DATA_ENCRYPTION'
    );
  });

  test('correct evidence-status fallback priority (evidence -> observability -> NOT_OBSERVABLE)', () => {
    // 1. Primary: evidence is used and uppercased
    const f1 = createSampleFinding({
      evidence: '  observed  ',
      observability: 'inferred',
    });
    assert.strictEqual(
      buildFindingExplanationRequest(f1).evidence_status,
      'OBSERVED'
    );

    // 2. Secondary: observability is used when evidence is empty
    const f2 = createSampleFinding({
      evidence: '',
      observability: '  inferred  ',
    });
    assert.strictEqual(
      buildFindingExplanationRequest(f2).evidence_status,
      'INFERRED'
    );

    // 3. Fallback: both missing
    const f3 = createSampleFinding({ evidence: '', observability: '' });
    assert.strictEqual(
      buildFindingExplanationRequest(f3).evidence_status,
      'NOT_OBSERVABLE'
    );
  });
});

describe('AIFindingExplainer - 3. Stale Responses & Request Identity Protection', () => {
  test('request identity string uniquely identifies identical requests and discriminates different findings', () => {
    const f1 = createSampleFinding({ id: 'F1', title: 'Finding One' });
    const f2 = createSampleFinding({ id: 'F2', title: 'Finding Two' });

    const p1 = buildFindingExplanationRequest(f1);
    const p2 = buildFindingExplanationRequest(f2);

    const id1 = JSON.stringify(p1);
    const id2 = JSON.stringify(p2);

    assert.notStrictEqual(id1, id2);
  });

  test('stale asynchronous response from older generation is dropped', () => {
    const currentGeneration = 2;
    const staleResponseGeneration = 1;
    const requestIdentity = JSON.stringify(
      buildFindingExplanationRequest(createSampleFinding())
    );

    const accept = shouldAcceptResponse(
      currentGeneration,
      staleResponseGeneration,
      requestIdentity,
      requestIdentity
    );

    assert.strictEqual(
      accept,
      false,
      'Stale generation response must NOT be accepted'
    );
  });

  test('response matching current generation and identity is accepted', () => {
    const currentGeneration = 2;
    const requestIdentity = JSON.stringify(
      buildFindingExplanationRequest(createSampleFinding())
    );

    const accept = shouldAcceptResponse(
      currentGeneration,
      currentGeneration,
      requestIdentity,
      requestIdentity
    );

    assert.strictEqual(
      accept,
      true,
      'Matching generation and identity must be accepted'
    );
  });

  test('response with mismatched identity is dropped even if generation matches', () => {
    const currentGeneration = 1;
    const idA = '{"rule_id":"FINDING-A"}';
    const idB = '{"rule_id":"FINDING-B"}';

    const accept = shouldAcceptResponse(
      currentGeneration,
      currentGeneration,
      idA,
      idB
    );

    assert.strictEqual(
      accept,
      false,
      'Mismatched identity must NOT be accepted'
    );
  });
});

describe('AIFindingExplainer - 4. Response Validation & Error Handling', () => {
  test('valid response with matching rule_id is accepted', () => {
    const requestRuleId = 'FINDING-RSA-2048';
    const responseData = createSampleExplanationResponse(requestRuleId);

    const result: AIExplanationResult<FindingExplanationResponse> = {
      success: true,
      data: responseData,
      is_available: true,
      provider: 'mock',
      disclaimer: 'AI Advisory',
    };

    const outcome = validateExplanationResponse(requestRuleId, result);

    assert.strictEqual(outcome.data?.rule_id, requestRuleId);
    assert.strictEqual(outcome.error, null);
    assert.strictEqual(outcome.unavailable, false);
  });

  test('response with mismatched rule_id is rejected with descriptive error', () => {
    const requestRuleId = 'FINDING-RSA-2048';
    // AI returned explanation for a different rule
    const mismatchedData = createSampleExplanationResponse('FINDING-ECC-P256');

    const result: AIExplanationResult<FindingExplanationResponse> = {
      success: true,
      data: mismatchedData,
      is_available: true,
      provider: 'mock',
      disclaimer: 'AI Advisory',
    };

    const outcome = validateExplanationResponse(requestRuleId, result);

    assert.strictEqual(
      outcome.data,
      null,
      'Data must be null for mismatched rule_id'
    );
    assert.ok(
      outcome.error?.includes('different finding'),
      'Error message must indicate different finding'
    );
    assert.strictEqual(outcome.unavailable, false);
  });

  test('provider unavailable state is correctly classified', () => {
    const requestRuleId = 'FINDING-RSA-2048';
    const result: AIExplanationResult<FindingExplanationResponse> = {
      success: false,
      is_available: false,
      provider: 'none',
      error: 'API key not configured.',
      disclaimer: 'AI Advisory',
    };

    const outcome = validateExplanationResponse(requestRuleId, result);

    assert.strictEqual(outcome.data, null);
    assert.strictEqual(outcome.unavailable, true);
    assert.strictEqual(outcome.error, 'API key not configured.');
  });

  test('generic provider error is correctly captured', () => {
    const requestRuleId = 'FINDING-RSA-2048';
    const result: AIExplanationResult<FindingExplanationResponse> = {
      success: false,
      is_available: true,
      provider: 'mock',
      error: 'Upstream rate limit reached.',
      disclaimer: 'AI Advisory',
    };

    const outcome = validateExplanationResponse(requestRuleId, result);

    assert.strictEqual(outcome.data, null);
    assert.strictEqual(outcome.unavailable, false);
    assert.strictEqual(outcome.error, 'Upstream rate limit reached.');
  });
});
