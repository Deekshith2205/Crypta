import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert';
import {
  buildResolvedUrl,
  extractApiErrorMessage,
  fetchWithFallback,
  DEFAULT_TIMEOUT_MS,
  DIRECT_BACKEND_ORIGIN,
  getAIStatus,
} from './api.ts';

describe('API Client - 1. URL Resolution & Constants', () => {
  test('constants conform to security & timeout specs', () => {
    assert.strictEqual(DEFAULT_TIMEOUT_MS, 15000, 'Default timeout must be 15000ms (15s)');
    assert.strictEqual(DIRECT_BACKEND_ORIGIN, 'http://127.0.0.1:8000');
  });

  test('buildResolvedUrl handles relative and absolute base paths correctly', () => {
    assert.strictEqual(buildResolvedUrl('/api/scan', ''), '/api/scan');
    assert.strictEqual(buildResolvedUrl('api/scan', ''), '/api/scan');
    assert.strictEqual(buildResolvedUrl('/api/scan', 'http://localhost:8000'), 'http://localhost:8000/api/scan');
    assert.strictEqual(buildResolvedUrl('/api/scan', 'http://localhost:8000/'), 'http://localhost:8000/api/scan');
    assert.strictEqual(buildResolvedUrl('api/ai/budget', 'https://api.quantumshield.io'), 'https://api.quantumshield.io/api/ai/budget');
  });
});

describe('API Client - 2. Error Message Extraction', () => {
  test('extracts detail string when present', () => {
    const errorData = { detail: 'Domain validation failed: invalid label.' };
    assert.strictEqual(
      extractApiErrorMessage(errorData, 400),
      'Domain validation failed: invalid label.'
    );
  });

  test('extracts error string when detail is absent', () => {
    const errorData = { error: 'RATE_LIMIT_EXCEEDED' };
    assert.strictEqual(
      extractApiErrorMessage(errorData, 429),
      'RATE_LIMIT_EXCEEDED'
    );
  });

  test('extracts message string when detail and error are absent', () => {
    const errorData = { message: 'Connection to HSM timed out.' };
    assert.strictEqual(
      extractApiErrorMessage(errorData, 504),
      'Connection to HSM timed out.'
    );
  });

  test('falls back to HTTP status when errorData is non-object or empty', () => {
    assert.strictEqual(
      extractApiErrorMessage(null, 502),
      'Request failed with HTTP 502'
    );
    assert.strictEqual(
      extractApiErrorMessage({}, 500),
      'Request failed with HTTP 500'
    );
    assert.strictEqual(
      extractApiErrorMessage('Plain text error', 404),
      'Request failed with HTTP 404'
    );
  });
});

describe('API Client - 3. Fetch with Fallback & Resilience', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test('successfully parses JSON on HTTP 200', async () => {
    const mockData = { status: 'healthy', version: '1.0.0' };
    globalThis.fetch = (async () => {
      return new Response(JSON.stringify(mockData), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;

    const result = await fetchWithFallback<typeof mockData>('/api/health');
    assert.deepStrictEqual(result, mockData);
  });

  test('throws structured error message on HTTP 400', async () => {
    globalThis.fetch = (async () => {
      return new Response(
        JSON.stringify({ detail: 'Prohibited target domain.' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }) as typeof fetch;

    await assert.rejects(
      async () => {
        await fetchWithFallback('/api/scan');
      },
      {
        message: 'Prohibited target domain.',
      }
    );
  });

  test('falls back to secondary origin when primary fetch throws network error', async () => {
    const calls: string[] = [];
    const mockData = { date: '2026-11-21', daily_token_budget: 100000 };

    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      calls.push(url);
      if (calls.length === 1) {
        throw new Error('Connection refused');
      }
      return new Response(JSON.stringify(mockData), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;

    const result = await fetchWithFallback<typeof mockData>('/api/ai/budget');
    assert.deepStrictEqual(result, mockData);
    assert.strictEqual(calls.length, 2);
    assert.strictEqual(calls[0], '/api/ai/budget');
    assert.strictEqual(calls[1], 'http://127.0.0.1:8000/api/ai/budget');
  });

  test('getAIStatus returns offline payload rather than throwing when backend is down', async () => {
    globalThis.fetch = (async () => {
      throw new Error('Network failure');
    }) as typeof fetch;

    const status = await getAIStatus();
    assert.strictEqual(status.is_available, false);
    assert.strictEqual(status.provider, 'none');
    assert.match(status.message, /Unable to connect|unavailable/i);
  });
});
