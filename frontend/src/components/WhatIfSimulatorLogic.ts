import type {
  MigrationComponent,
  MigrationAction,
  WhatIfMigrationRequest,
} from '../types/scan.ts';

export const MAX_SIMULTANEOUS_CHANGES = 5;

export const SUPPORTED_TARGETS: Record<
  MigrationComponent,
  { value: string; label: string; desc: string }[]
> = {
  KEY_WRAPPING: [
    {
      value: 'ML-KEM-768',
      label: 'ML-KEM-768 (FIPS 203)',
      desc: 'NIST Standardized Category 3 Lattice KEM (Primary)',
    },
    {
      value: 'ML-KEM-1024',
      label: 'ML-KEM-1024 (FIPS 203)',
      desc: 'NIST Category 5 Maximum Security Lattice KEM',
    },
    {
      value: 'X25519MLKEM768',
      label: 'X25519MLKEM768 Hybrid',
      desc: 'IETF RFC 9870 Hybrid Classical + PQC KEM',
    },
    {
      value: 'AES-256-KW',
      label: 'AES-256 Key Wrap (NIST SP 800-38F)',
      desc: 'Symmetric Key Wrap (Grover Resilient)',
    },
  ],
  AUTHENTICATION: [
    {
      value: 'ML-DSA-65',
      label: 'ML-DSA-65 (FIPS 204)',
      desc: 'NIST Standardized Lattice Signature (Primary)',
    },
    {
      value: 'ML-DSA-87',
      label: 'ML-DSA-87 (FIPS 204)',
      desc: 'NIST Category 5 High Security Lattice Signature',
    },
    {
      value: 'SLH-DSA-128s',
      label: 'SLH-DSA-128s (FIPS 205)',
      desc: 'Stateless Hash-Based Digital Signature Standard',
    },
    {
      value: 'SLH-DSA-128f',
      label: 'SLH-DSA-128f (FIPS 205)',
      desc: 'Fast Hash-Based Digital Signature',
    },
  ],
  TLS_PROTOCOL: [
    {
      value: 'TLSv1.3',
      label: 'TLS 1.3 (RFC 8446)',
      desc: 'Modern Transport Protocol removing obsolete ciphers',
    },
  ],
  TLS_KEY_EXCHANGE: [
    {
      value: 'X25519MLKEM768',
      label: 'X25519MLKEM768 Hybrid (0x11ec)',
      desc: 'IETF Draft Hybrid Key Agreement for TLS 1.3',
    },
    {
      value: 'SecP256r1MLKEM768',
      label: 'SecP256r1MLKEM768 Hybrid (0x11ed)',
      desc: 'NIST P-256 + ML-KEM-768 Hybrid Key Agreement',
    },
    {
      value: 'X448MLKEM1024',
      label: 'X448MLKEM1024 Hybrid (0x11ee)',
      desc: 'X448 + ML-KEM-1024 High Security Hybrid Group',
    },
  ],
};

/**
 * Adds a new migration action up to MAX_SIMULTANEOUS_CHANGES (5).
 */
export function addSimulationChange(changes: MigrationAction[]): MigrationAction[] {
  if (changes.length >= MAX_SIMULTANEOUS_CHANGES) {
    return changes;
  }
  return [
    ...changes,
    {
      component: 'AUTHENTICATION',
      target_algorithm: 'ML-DSA-65',
      description: 'Upgrade root authentication signatures to FIPS 204 ML-DSA',
    },
  ];
}

/**
 * Removes a migration action by index, preserving at least one action.
 */
export function removeSimulationChange(changes: MigrationAction[], index: number): MigrationAction[] {
  if (changes.length <= 1) {
    return changes;
  }
  return changes.filter((_, i) => i !== index);
}

/**
 * Updates a migration action by index, ensuring algorithm validity for the selected component.
 */
export function updateSimulationChange(
  changes: MigrationAction[],
  index: number,
  updated: Partial<MigrationAction>
): MigrationAction[] {
  if (index < 0 || index >= changes.length) {
    return changes;
  }

  const next = [...changes];
  const current = next[index];
  const newComponent = updated.component || current.component;
  let newTarget = updated.target_algorithm || current.target_algorithm;

  const allowed = SUPPORTED_TARGETS[newComponent];
  if (!allowed || !allowed.some((opt) => opt.value === newTarget)) {
    newTarget = allowed ? allowed[0].value : 'ML-KEM-768';
  }

  next[index] = {
    ...current,
    ...updated,
    component: newComponent,
    target_algorithm: newTarget,
  };

  return next;
}

/**
 * Returns preconfigured migration presets.
 */
export function getSimulationPreset(
  presetType: 'wrapping' | 'auth' | 'full' | 'transport'
): MigrationAction[] {
  switch (presetType) {
    case 'wrapping':
      return [
        {
          component: 'KEY_WRAPPING',
          target_algorithm: 'ML-KEM-768',
          description: 'Migrate asymmetric key wrapping to NIST FIPS 203 ML-KEM-768',
        },
      ];
    case 'auth':
      return [
        {
          component: 'AUTHENTICATION',
          target_algorithm: 'ML-DSA-65',
          description: 'Upgrade root authentication signatures to FIPS 204 ML-DSA-65',
        },
      ];
    case 'transport':
      return [
        {
          component: 'TLS_PROTOCOL',
          target_algorithm: 'TLSv1.3',
          description: 'Enforce TLS 1.3 transport security protocol',
        },
        {
          component: 'TLS_KEY_EXCHANGE',
          target_algorithm: 'X25519MLKEM768',
          description: 'Adopt X25519MLKEM768 post-quantum hybrid key exchange',
        },
      ];
    case 'full':
      return [
        {
          component: 'KEY_WRAPPING',
          target_algorithm: 'ML-KEM-768',
          description: 'NIST FIPS 203 ML-KEM-768 key encapsulation',
        },
        {
          component: 'AUTHENTICATION',
          target_algorithm: 'ML-DSA-65',
          description: 'NIST FIPS 204 ML-DSA-65 digital signatures',
        },
        {
          component: 'TLS_PROTOCOL',
          target_algorithm: 'TLSv1.3',
          description: 'TLS 1.3 transport protocol',
        },
        {
          component: 'TLS_KEY_EXCHANGE',
          target_algorithm: 'X25519MLKEM768',
          description: 'Hybrid X25519MLKEM768 key exchange',
        },
      ];
  }
}

/**
 * Computes score delta between baseline and projected scores.
 */
export function computeScoreDelta(
  baselineScore: number,
  projectedScore: number
): { scoreDiff: number; improved: boolean; percentReduction: number } {
  const scoreDiff = baselineScore - projectedScore;
  const improved = scoreDiff > 0;
  const percentReduction = baselineScore > 0
    ? Math.round((Math.max(0, scoreDiff) / baselineScore) * 100)
    : 0;

  return {
    scoreDiff,
    improved,
    percentReduction,
  };
}

/**
 * Validates whether simulation parameters are ready for submission.
 */
export function validateSimulationRequest(
  assetId: string,
  changes: MigrationAction[]
): { isValid: boolean; error?: string } {
  if (!assetId || !assetId.trim()) {
    return { isValid: false, error: 'Please select a banking asset.' };
  }
  if (!changes || changes.length === 0) {
    return { isValid: false, error: 'At least one migration change is required.' };
  }
  if (changes.length > MAX_SIMULTANEOUS_CHANGES) {
    return {
      isValid: false,
      error: `Maximum of ${MAX_SIMULTANEOUS_CHANGES} simultaneous changes allowed.`,
    };
  }
  return { isValid: true };
}

/**
 * Constructs the typed WhatIfMigrationRequest payload.
 */
export function buildWhatIfPayload(
  assetId: string,
  changes: MigrationAction[]
): WhatIfMigrationRequest {
  return {
    asset_id: assetId.trim(),
    changes: changes.map((c) => ({
      component: c.component,
      target_algorithm: c.target_algorithm,
      description: c.description || '',
    })),
  };
}