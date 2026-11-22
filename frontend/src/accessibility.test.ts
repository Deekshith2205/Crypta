/**
 * Automated Accessibility Unit Tests (Task 5 Remediation - Phase E).
 * Verifies ARIA roles, modal contracts, keyboard navigation triggers,
 * form labels, live regions, and screen-reader announcements across QuantumShield UI.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

// Helper to read component source files directly for static AST / semantic attribute assertions
const readComponentSource = (relativePath: string): string => {
  const fullPath = path.resolve(process.cwd(), 'src', relativePath);
  return fs.readFileSync(fullPath, 'utf-8');
};

describe('Phase E Frontend Accessibility & ARIA Contract Verification', () => {
  describe('1. Modal Dialog Semantics & Focus Management', () => {
    it('CBOMModal conforms to WAI-ARIA Modal Dialog Pattern', () => {
      const src = readComponentSource('components/CBOMModal.tsx');

      // Must specify dialog role and modal property
      assert.match(src, /role="dialog"/, 'CBOMModal must have role="dialog"');
      assert.match(src, /aria-modal="true"/, 'CBOMModal must have aria-modal="true"');

      // Must associate title with aria-labelledby
      assert.match(src, /aria-labelledby="cbom-modal-title"/, 'CBOMModal must reference its title via aria-labelledby');
      assert.match(src, /id="cbom-modal-title"/, 'CBOMModal title must have matching id');

      // Close button must have descriptive aria-label
      assert.match(src, /aria-label="Close CBOM dialog"/, 'CBOM close button must have accessible aria-label');

      // Must support keyboard Escape listener
      assert.match(src, /e\.key === 'Escape'/, 'CBOMModal must handle Escape key for keyboard dismissal');
    });

    it('JsonExportModal conforms to WAI-ARIA Modal Dialog Pattern', () => {
      const src = readComponentSource('components/JsonExportModal.tsx');

      assert.match(src, /role="dialog"/, 'JsonExportModal must have role="dialog"');
      assert.match(src, /aria-modal="true"/, 'JsonExportModal must have aria-modal="true"');
      assert.match(src, /aria-labelledby="json-export-title"/, 'JsonExportModal must have aria-labelledby');
      assert.match(src, /id="json-export-title"/, 'JsonExportModal title must have matching id');
      assert.match(src, /aria-label="Close JSON report dialog"/, 'JsonExportModal close button must have aria-label');
      assert.match(src, /e\.key === 'Escape'/, 'JsonExportModal must handle Escape key');
    });

    it('StandardsModal conforms to WAI-ARIA Modal Dialog Pattern', () => {
      const src = readComponentSource('components/StandardsModal.tsx');

      assert.match(src, /role="dialog"/, 'StandardsModal must have role="dialog"');
      assert.match(src, /aria-modal="true"/, 'StandardsModal must have aria-modal="true"');
      assert.match(src, /aria-labelledby="standards-modal-title"/, 'StandardsModal must have aria-labelledby');
      assert.match(src, /id="standards-modal-title"/, 'StandardsModal title must have matching id');
      assert.match(src, /aria-label="Close standards reference dialog"/, 'StandardsModal close button must have aria-label');
      assert.match(src, /e\.key === 'Escape'/, 'StandardsModal must handle Escape key');
    });

    it('AIBankingRiskModal conforms to WAI-ARIA Modal Dialog Pattern', () => {
      const src = readComponentSource('components/ai/AIBankingRiskModal.tsx');

      assert.match(src, /role="dialog"/, 'AIBankingRiskModal must have role="dialog"');
      assert.match(src, /aria-modal="true"/, 'AIBankingRiskModal must have aria-modal="true"');
      assert.match(src, /aria-labelledby="ai-banking-risk-title"/, 'AIBankingRiskModal must have aria-labelledby');
      assert.match(src, /id="ai-banking-risk-title"/, 'AIBankingRiskModal title must have matching id');
      assert.match(src, /aria-label="Close risk explanation"/, 'AIBankingRiskModal close button must have aria-label');
      assert.match(src, /e\.key === 'Escape'/, 'AIBankingRiskModal must handle Escape key');
    });

    it('AIMigrationAdvisorModal conforms to WAI-ARIA Modal Dialog Pattern', () => {
      const src = readComponentSource('components/ai/AIMigrationAdvisorModal.tsx');

      assert.match(src, /role="dialog"/, 'AIMigrationAdvisorModal must have role="dialog"');
      assert.match(src, /aria-modal="true"/, 'AIMigrationAdvisorModal must have aria-modal="true"');
      assert.match(src, /aria-labelledby="ai-migration-advisor-title"/, 'AIMigrationAdvisorModal must have aria-labelledby');
      assert.match(src, /id="ai-migration-advisor-title"/, 'AIMigrationAdvisorModal title must have matching id');
      assert.match(src, /aria-label="Close migration advisor dialog"/, 'AIMigrationAdvisorModal close button must have aria-label');
      assert.match(src, /e\.key === 'Escape'/, 'AIMigrationAdvisorModal must handle Escape key');
    });
  });

  describe('2. Form Accessibility & Screen Reader Labeling', () => {
    it('DomainScannerInput contains accessible input and submit labels', () => {
      const src = readComponentSource('components/landing/DomainScannerInput.tsx');

      // Input must have descriptive aria-label
      assert.match(src, /aria-label="Target domain name for cryptographic readiness scan"/);

      // Button must have descriptive aria-label
      assert.match(src, /aria-label="Start TLS post-quantum readiness scan"/);

      // Validation alerts must have role="alert" and aria-live="polite"
      assert.match(src, /role="alert"/);
      assert.match(src, /aria-live="polite"/);

      // Warnings must have role="status"
      assert.match(src, /role="status"/);
    });

    it('DomainInput contains accessible input label and error role', () => {
      const src = readComponentSource('components/DomainInput.tsx');

      assert.match(src, /aria-label="Domain name to scan"/);
      assert.match(src, /aria-label="Start domain cryptographic scan"/);
      assert.match(src, /role="alert"/);
      assert.match(src, /aria-live="polite"/);
    });

    it('ArtifactUploadPanel associates label with file input and declares alert role', () => {
      const src = readComponentSource('components/ArtifactUploadPanel.tsx');

      assert.match(src, /htmlFor="artifact-upload-input"/);
      assert.match(src, /id="artifact-upload-input"/);
      assert.match(src, /role="alert"/);
      assert.match(src, /focus-within:ring-2/);
    });
  });

  describe('3. Keyboard Navigation & Focus Ring Indicators', () => {
    it('Header Brand element supports keyboard activation (Enter & Space)', () => {
      const src = readComponentSource('components/landing/Header.tsx');

      assert.match(src, /role="button"/);
      assert.match(src, /tabIndex=\{0\}/);
      assert.match(src, /e\.key === 'Enter' \|\| e\.key === ' '/);
      assert.match(src, /focus-visible:ring-2/);
    });

    it('AIFindingExplainer toggle button indicates expanded state to assistive tech', () => {
      const src = readComponentSource('components/ai/AIFindingExplainer.tsx');

      assert.match(src, /aria-expanded=\{isOpen\}/);
      assert.match(src, /focus-visible:ring-2/);
      assert.match(src, /aria-label=\{isOpen \? 'Hide AI reasoning for finding' : 'Explain finding with AI'\}/);
    });
  });
});
