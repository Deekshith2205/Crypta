import { test, describe } from 'node:test';
import assert from 'node:assert';
import {
  addSimulationChange,
  removeSimulationChange,
  updateSimulationChange,
  getSimulationPreset,
  computeScoreDelta,
  validateSimulationRequest,
  buildWhatIfPayload,
  MAX_SIMULTANEOUS_CHANGES,
} from './WhatIfSimulatorLogic.ts';
import type { MigrationAction } from '../types/scan.ts';

const initialChange: MigrationAction = {
  component: 'KEY_WRAPPING',
  target_algorithm: 'ML-KEM-768',
  description: 'Upgrade key wrapping',
};

describe('What-If Simulator Logic - 1. Action List Manipulation', () => {
  test('adds changes up to maximum limit (5)', () => {
    let list: MigrationAction[] = [initialChange];
    for (let i = 0; i < 6; i++) {
      list = addSimulationChange(list);
    }
    assert.strictEqual(list.length, MAX_SIMULTANEOUS_CHANGES);
  });

  test('removes change by index but preserves at least one change', () => {
    const list: MigrationAction[] = [
      initialChange,
      { component: 'AUTHENTICATION', target_algorithm: 'ML-DSA-65', description: 'auth' },
    ];
    const afterOneRemoval = removeSimulationChange(list, 0);
    assert.strictEqual(afterOneRemoval.length, 1);
    assert.strictEqual(afterOneRemoval[0].component, 'AUTHENTICATION');

    // Removing when length is 1 should be a no-op
    const noOpRemoval = removeSimulationChange(afterOneRemoval, 0);
    assert.strictEqual(noOpRemoval.length, 1);
  });

  test('updates component and resets target algorithm if invalid for new component', () => {
    const list: MigrationAction[] = [initialChange];
    // Switch from KEY_WRAPPING to AUTHENTICATION without specifying target_algorithm
    const updated = updateSimulationChange(list, 0, { component: 'AUTHENTICATION' });
    assert.strictEqual(updated[0].component, 'AUTHENTICATION');
    assert.strictEqual(updated[0].target_algorithm, 'ML-DSA-65'); // default first option
  });
});

describe('What-If Simulator Logic - 2. Presets & Score Computation', () => {
  test('returns valid migration presets', () => {
    const wrapping = getSimulationPreset('wrapping');
    assert.strictEqual(wrapping.length, 1);
    assert.strictEqual(wrapping[0].component, 'KEY_WRAPPING');

    const auth = getSimulationPreset('auth');
    assert.strictEqual(auth.length, 1);
    assert.strictEqual(auth[0].component, 'AUTHENTICATION');

    const transport = getSimulationPreset('transport');
    assert.strictEqual(transport.length, 2);

    const full = getSimulationPreset('full');
    assert.strictEqual(full.length, 4);
  });

  test('computes score delta and improvement percentage accurately', () => {
    const delta = computeScoreDelta(80, 20);
    assert.strictEqual(delta.scoreDiff, 60);
    assert.strictEqual(delta.improved, true);
    assert.strictEqual(delta.percentReduction, 75);

    const regressed = computeScoreDelta(50, 60);
    assert.strictEqual(regressed.scoreDiff, -10);
    assert.strictEqual(regressed.improved, false);
    assert.strictEqual(regressed.percentReduction, 0);
  });
});

describe('What-If Simulator Logic - 3. Payload Validation & Building', () => {
  test('validates simulation request parameters', () => {
    assert.strictEqual(validateSimulationRequest('', [initialChange]).isValid, false);
    assert.strictEqual(validateSimulationRequest('BANK-PROF-1', []).isValid, false);
    assert.strictEqual(validateSimulationRequest('BANK-PROF-1', [initialChange]).isValid, true);
  });

  test('builds valid WhatIfMigrationRequest payload', () => {
    const payload = buildWhatIfPayload('BANK-PROF-1', [initialChange]);
    assert.strictEqual(payload.asset_id, 'BANK-PROF-1');
    assert.strictEqual(payload.simulated_changes.length, 1);
    assert.strictEqual(payload.simulated_changes[0].component, 'KEY_WRAPPING');
    assert.strictEqual(payload.simulated_changes[0].target_algorithm, 'ML-KEM-768');
  });
});
