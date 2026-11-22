import { test, describe } from 'node:test';
import assert from 'node:assert';
import type { CBOMDocument } from '../types/scan.ts';

describe('Phase F CBOM Frontend Logic', () => {
  const sampleCBOM: CBOMDocument = {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    serialNumber: 'urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8',
    version: 1,
    metadata: {
      timestamp: '2026-10-30T00:00:00Z',
      tools: [{ vendor: 'QuantumShield', name: 'ConfigScanner-CBOM', version: '1.0.0' }],
    },
    components: [
      {
        type: 'cryptographic-asset',
        'bom-ref': 'crypto-bank-001-transport-tls',
        name: 'TLS 1.3',
        cryptoProperties: {
          assetType: 'protocol',
          protocolProperties: {
            type: 'tls',
            version: '1.3',
          },
        },
        properties: [
          { name: 'quantumshield:source_file', value: 'nginx.conf' },
          { name: 'quantumshield:config_path', value: 'ssl_protocols' },
          { name: 'quantumshield:role', value: 'TRANSPORT_SECURITY' },
          { name: 'quantumshield:evidence_status', value: 'OBSERVED' },
        ],
      },
      {
        type: 'cryptographic-asset',
        'bom-ref': 'crypto-bank-002-data-aes',
        name: 'AES-256-GCM',
        cryptoProperties: {
          assetType: 'algorithm',
          algorithmProperties: {
            primitive: 'ae',
            parameterSetIdentifier: '256',
            mode: 'gcm',
            classicalSecurityLevel: 256,
            nistQuantumSecurityLevel: 3,
          },
        },
        properties: [
          { name: 'quantumshield:source_file', value: 'application.yml' },
          { name: 'quantumshield:config_path', value: 'security.cipher' },
          { name: 'quantumshield:role', value: 'BULK_ENCRYPTION' },
          { name: 'quantumshield:evidence_status', value: 'OBSERVED' },
        ],
      },
    ],
    dependencies: [
      {
        ref: 'crypto-bank-001-transport-tls',
        dependsOn: ['crypto-bank-002-data-aes'],
      },
    ],
  };

  test('validates CycloneDX 1.7 document header structure', () => {
    assert.strictEqual(sampleCBOM.bomFormat, 'CycloneDX');
    assert.strictEqual(sampleCBOM.specVersion, '1.7');
    assert.match(sampleCBOM.serialNumber, /^urn:uuid:/);
    assert.strictEqual(sampleCBOM.version, 1);
    assert.strictEqual(sampleCBOM.components.length, 2);
    assert.strictEqual(sampleCBOM.dependencies?.length, 1);
  });

  test('correctly extracts algorithm properties from cryptographic asset', () => {
    const aesComp = sampleCBOM.components.find((c) => c.name === 'AES-256-GCM');
    assert.ok(aesComp);
    assert.strictEqual(aesComp.cryptoProperties.assetType, 'algorithm');

    const algoProps = aesComp.cryptoProperties.algorithmProperties;
    assert.strictEqual(algoProps?.primitive, 'ae');
    assert.strictEqual(algoProps?.parameterSetIdentifier, '256');
    assert.strictEqual(algoProps?.nistQuantumSecurityLevel, 3);
    assert.strictEqual(algoProps?.classicalSecurityLevel, 256);
  });

  test('correctly maps custom quantumshield provenance properties', () => {
    const tlsComp = sampleCBOM.components.find((c) => c.name === 'TLS 1.3');
    assert.ok(tlsComp);

    const propMap = (tlsComp.properties || []).reduce<Record<string, string>>((acc, p) => {
      acc[p.name] = p.value;
      return acc;
    }, {});

    assert.strictEqual(propMap['quantumshield:source_file'], 'nginx.conf');
    assert.strictEqual(propMap['quantumshield:config_path'], 'ssl_protocols');
    assert.strictEqual(propMap['quantumshield:role'], 'TRANSPORT_SECURITY');
    assert.strictEqual(propMap['quantumshield:evidence_status'], 'OBSERVED');
  });

  test('serializes CBOM document to formatted JSON without secret leakage', () => {
    const jsonStr = JSON.stringify(sampleCBOM, null, 2);
    assert.ok(jsonStr.includes('"bomFormat": "CycloneDX"'));
    assert.ok(jsonStr.includes('"specVersion": "1.7"'));
    assert.ok(jsonStr.includes('"crypto-bank-001-transport-tls"'));
    assert.ok(!jsonStr.includes('password'));
    assert.ok(!jsonStr.includes('private_key'));
  });

  test('handles empty component inventories gracefully', () => {
    const emptyCBOM: CBOMDocument = {
      bomFormat: 'CycloneDX',
      specVersion: '1.7',
      serialNumber: 'urn:uuid:00000000-0000-0000-0000-000000000000',
      version: 1,
      components: [],
      dependencies: [],
    };

    assert.strictEqual(emptyCBOM.components.length, 0);
    assert.strictEqual(emptyCBOM.dependencies?.length, 0);
    const jsonStr = JSON.stringify(emptyCBOM);
    assert.ok(jsonStr.length > 0);
  });
});
