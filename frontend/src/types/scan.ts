export type TargetInfo = {
  domain: string;
  port: number;
  resolved_ip: string;
  ip_version: string;
  scan_timestamp: string;
  connection_time_ms: number;
  all_resolved_ips?: string[];
};

export type CertificateSummary = {
  subject_cn?: string;
  issuer_cn?: string;
  public_key_algorithm: string;
  key_size_bits?: number;
  curve_name?: string;
  signature_algorithm: string;
  fingerprint_sha256: string;
  not_valid_after: string;
};

export type CertificateInfo = {
  subject_cn?: string;
  subject_org?: string;
  subject_alt_names: string[];
  issuer_cn?: string;
  issuer_org?: string;
  serial_number: string;
  fingerprint_sha256: string;
  not_valid_before: string;
  not_valid_after: string;
  days_remaining: number;
  is_expired: boolean;
  public_key_algorithm: string;
  key_size_bits?: number;
  curve_name?: string;
  signature_algorithm: string;
  signature_hash_algorithm?: string;
  chain_length: number;
  chain_certificates: CertificateSummary[];
  verification_status: string;
  is_trusted: boolean;
};

export type PqcKeyExchangeEvidence = {
  raw_group: string;
  status: 'OBSERVED' | 'CAPABILITY_PROBED' | 'CLASSICAL_ONLY_OBSERVED' | 'PROBED_UNSUPPORTED' | 'NOT_OBSERVABLE' | string;
  classical_component?: string;
  pqc_component?: string;
  is_hybrid: boolean;
  source: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | string;
  probe_attempted: boolean;
  requested_group?: string;
  probe_result?: string;
  details?: string;
};

export type TlsInfo = {
  negotiated_protocol: string;
  negotiated_cipher: string;
  cipher_bits: number;
  alpn_protocol?: string;
  session_reused: boolean;
  key_exchange_value?: string;
  key_exchange_evidence?: 'OBSERVED' | 'CAPABILITY_PROBED' | 'CLASSICAL_ONLY_OBSERVED' | 'PROBED_UNSUPPORTED' | 'NOT_OBSERVABLE' | 'INFERRED' | string;
  key_exchange_inferred?: string;
  symmetric_encryption_inferred?: string;
  hash_mac_inferred?: string;
  pqc_evidence?: PqcKeyExchangeEvidence;
};

export type NormalizedCryptoMechanism = {
  role: string;
  value: string;
  source: string;
  evidence: 'OBSERVED' | 'INFERRED' | 'NOT_OBSERVABLE' | string;
  component: string;
  algorithm_family: string;
  algorithm_name: string;
  category: string;
  key_size?: number;
  curve?: string;
  observability: 'OBSERVED' | 'INFERRED' | 'NOT_OBSERVABLE' | string;
  evidence_source: string;
  raw_observed_value: string;
};

export type QuantumFinding = {
  id: string;
  title: string;
  role: string;
  value: string;
  source: string;
  evidence: 'OBSERVED' | 'INFERRED' | 'NOT_OBSERVABLE' | string;
  component: string;
  algorithm: string;
  category: string;
  quantum_threat: string;
  quantum_threat_vector: string;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  security_impact: string;
  reason: string;
  recommendation: string;
  migration_target: string;
  priority: 'P0' | 'P1' | 'P2' | 'P3' | string;
  priority_score: number;
  observed_from: string;
  observability: string;
  target_pqc_standard?: string;
};

export type CategoryScoreBreakdown = {
  certificates: number;
  key_establishment: number;
  symmetric_encryption: number;
  hashing: number;
  tls_configuration: number;
};

export type ScoreBreakdownItem = {
  factor: string;
  impact: string;
  points: number;
  explanation: string;
};

export type QuantumScore = {
  score: number; // 0 = extremely poor, 100 = excellent readiness
  readiness_score: number;
  exposure_risk_score: number;
  grade: 'Excellent' | 'Good' | 'Moderate' | 'Needs Improvement' | 'Critical';
  summary: string;
  category_breakdown: CategoryScoreBreakdown;
  score_breakdown: ScoreBreakdownItem[];
  methodology_disclaimer: string;
  formula_description: string;
};

export type RoleCategoryAssessment = {
  category_id: string;
  category_name: string;
  status: 'EXCELLENT' | 'GOOD' | 'MODERATE' | 'HIGH RISK' | 'CRITICAL' | 'INFORMATIONAL' | string;
  readiness_score: number;
  weight_percentage: number;
  observed_value: string;
  evidence: 'OBSERVED' | 'INFERRED' | 'NOT_OBSERVABLE' | string;
  source: string;
  quantum_threat: string;
  migration_target: string;
  priority: 'P0' | 'P1' | 'P2' | 'P3' | string;
  recommended_action: string;
  findings: QuantumFinding[];
};

export type ExecutiveSummary = {
  domain: string;
  readiness_verdict: string;
  primary_concern: string;
  secondary_concern?: string;
  visibility_limitations: string;
  recommended_next_steps: string[];
  full_text: string;
};

export type MigrationStep = {
  priority: 'P0' | 'P1' | 'P2' | 'P3' | string;
  priority_rank: number;
  title: string;
  affected_component: string;
  current_mechanism: string;
  reason: string;
  recommended_target: string;
  migration_approach: string;
  evidence: 'OBSERVED' | 'INFERRED' | 'NOT_OBSERVABLE' | string;
  urgency: string;
  target_standards: string[];
  // Backwards compatibility
  risk_level?: string;
  why_it_matters?: string;
  recommended_action?: string;
  migration_urgency?: string;
  observability?: string;
};

export type ObservabilityScope = {
  observed_externally: string[];
  potentially_inferred: string[];
  not_externally_observable: string[];
};

export type BankingAssetType =
  // Phase 4A Systems
  | 'NET_BANKING_PORTAL'
  | 'MOBILE_BANKING_API'
  | 'PAYMENT_GATEWAY'
  | 'UPI_PAYMENT_SERVICE'
  | 'CARD_PROCESSING'
  | 'CORE_BANKING'
  | 'CUSTOMER_DATABASE'
  | 'PAYMENT_DATABASE'
  | 'INTER_BANK_GATEWAY'
  | 'ATM_NETWORK'
  | 'ADMIN_PORTAL'
  | 'AUTHENTICATION_SERVICE'
  | 'NOTIFICATION_SERVICE'
  | 'INTERNAL_SERVICE'
  | 'OTHER'
  // Legacy Phase 0 types
  | 'PUBLIC_WEBSITE'
  | 'WEB_BANKING'
  | 'MOBILE_API'
  | 'API_GATEWAY'
  | 'PAYMENT_SERVICE'
  | 'TRANSACTION_SERVICE'
  | 'ACCOUNT_SERVICE';

export type AssetCriticality = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type DataSensitivity = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'HIGHLY_SENSITIVE';
export type AssetExposure = 'INTERNET' | 'PARTNER' | 'INTERNAL' | 'RESTRICTED';
export type DataLifetime = 'SHORT' | 'MEDIUM' | 'LONG' | 'VERY_LONG';
export type MigrationEffort = 'LOW' | 'MEDIUM' | 'HIGH' | 'VERY_HIGH';
export type TrustZone = 'PUBLIC' | 'DMZ' | 'APPLICATION' | 'DATA' | 'ADMIN' | 'THIRD_PARTY';

export type SecurityLayer =
  | 'EDGE'
  | 'API_GATEWAY'
  | 'SERVICE_TO_SERVICE'
  | 'DATA_AND_KEYS'
  | 'ADMINISTRATIVE';

export type EvidenceSource =
  | 'EXTERNAL_SCAN'
  | 'OPERATOR_DECLARED'
  | 'CONFIGURATION_FILE'
  | 'INFERRED';

export type EvidenceGapType =
  | 'INTERNAL_MTLS'
  | 'HSM_USAGE'
  | 'KMS_USAGE'
  | 'KEY_ROTATION'
  | 'DATABASE_ENCRYPTION_AT_REST'
  | 'PRIVILEGED_ACCESS_POLICY'
  | 'MFA_POLICY'
  | 'SERVICE_IDENTITY'
  | 'LEAST_PRIVILEGE'
  | 'CONTINUOUS_VERIFICATION'
  | 'KEY_WRAPPING'
  | 'INTERNAL_CERTIFICATE_POLICY';

export type KeyProtectionChain = {
  data_encryption?: string;
  key_wrapping?: string;
  key_storage?: string;
  authentication?: string;
};

export type CryptoConfiguration = {
  tls_versions: string[];
  cipher_suites: string[];
  key_exchange?: string;
  certificates: string[];
  signature_algorithm?: string;
  certificate_key_algorithm?: string;
  certificate_key_size?: number;
  data_encryption_algorithm?: string;
  key_wrapping_algorithm?: string;
  key_storage?: string;
  kms_or_hsm?: string;
  key_chain?: KeyProtectionChain;
};

export type EvidenceItem = {
  id: string;
  control: string;
  value: string;
  source: EvidenceSource;
  observability: ObservabilityState | string;
  confidence?: string;
  description?: string;
  layer?: SecurityLayer;
  metadata?: Record<string, unknown>;
};

export type EvidenceGap = {
  gap_type: EvidenceGapType;
  layer: SecurityLayer;
  control: string;
  description: string;
  evidence_needed: string;
  observability: ObservabilityState | string;
  source?: EvidenceSource;
};

export type BankingAsset = {
  id: string;
  name: string;
  asset_type: BankingAssetType;
  system_type?: BankingAssetType;
  description: string;
  criticality: AssetCriticality;
  data_sensitivity: DataSensitivity;
  exposure: AssetExposure;
  data_lifetime: DataLifetime;
  trust_zone: TrustZone;
  migration_effort?: MigrationEffort;
  tags: string[];
  layers?: Partial<Record<SecurityLayer, EvidenceItem[]>>;
  cryptography?: CryptoConfiguration;
  key_management?: Record<string, unknown>;
  authentication?: Record<string, unknown>;
  evidence_items?: EvidenceItem[];
  evidence_gaps?: EvidenceGap[];
  metadata?: Record<string, unknown>;
};

export type BankingSystemProfile = BankingAsset;

export type AuditDomain =
  | 'CRYPTOGRAPHY'
  | 'QUANTUM_SECURITY'
  | 'ZERO_TRUST'
  | 'IDENTITY'
  | 'ACCESS_CONTROL'
  | 'NETWORK_SECURITY'
  | 'CONFIGURATION'
  | 'CLASSICAL_SECURITY';

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type RemediationPriority = 'P0' | 'P1' | 'P2' | 'P3';
export type ObservabilityState =
  | 'OBSERVED'
  | 'NOT_OBSERVABLE'
  | 'CAPABILITY_PROBED'
  | 'PROBED_UNSUPPORTED'
  | 'CLASSICAL_ONLY_OBSERVED';

export type AuditFinding = {
  id: string;
  asset_id: string;
  domain: AuditDomain;
  control: string;
  title: string;
  severity: FindingSeverity;
  evidence: string;
  evidence_source: string;
  observability: ObservabilityState;
  impact: string;
  recommendation: string;
  remediation_priority: RemediationPriority;
  metadata?: Record<string, unknown>;
};

export type ZeroTrustPillar =
  | 'IDENTITY'
  | 'DEVICE_CONTEXT'
  | 'RESOURCE'
  | 'POLICY'
  | 'LEAST_PRIVILEGE'
  | 'CONTINUOUS_VERIFICATION';

export type ZeroTrustControlStatus =
  | 'VERIFIED'
  | 'PARTIALLY_VERIFIED'
  | 'NOT_OBSERVABLE_EXTERNALLY'
  | 'UNVERIFIED';

export type ZeroTrustControl = {
  pillar: ZeroTrustPillar;
  control_id: string;
  name: string;
  status: ZeroTrustControlStatus;
  observability: ObservabilityState;
  description: string;
  evidence?: string;
  notes?: string;
};

export type ZeroTrustAssessment = {
  asset_id: string;
  identity_control: ZeroTrustControl;
  context_control: ZeroTrustControl;
  resource_control: ZeroTrustControl;
  policy_control: ZeroTrustControl;
  least_privilege_control: ZeroTrustControl;
  continuous_verification_control: ZeroTrustControl;
  findings: AuditFinding[];
};

export type KeyChainStatus =
  | 'QUANTUM_READY'
  | 'PARTIALLY_QUANTUM_READY'
  | 'QUANTUM_EXPOSED'
  | 'INSUFFICIENT_EVIDENCE';

export type MigrationPriority = 'P0' | 'P1' | 'P2' | 'P3';

export type KeyChainAnalysis = {
  status: KeyChainStatus;
  weak_links: string[];
  data_encryption_status: string;
  data_encryption_algorithm?: string;
  key_wrapping_status: string;
  key_wrapping_algorithm?: string;
  key_storage_status: string;
  key_storage_facility?: string;
  authentication_status: string;
  authentication_algorithm?: string;
  primary_migration_dependencies: string[];
  notes: string;
  agility_score?: number;
  agility_rating?: string;
  agility_rationale?: string;
};

export type TechnicalRiskContext = {
  quantum_risk_level: number;
  quantum_risk_label: string;
  classical_risk_level: number;
  classical_risk_label: string;
  governing_technical_risk: number;
};

export type BusinessRiskContext = {
  criticality_score: number;
  criticality_label: string;
  sensitivity_score: number;
  sensitivity_label: string;
  lifetime_score: number;
  lifetime_label: string;
  exposure_score: number;
  exposure_label: string;
  migration_effort_score: number;
  migration_effort_label: string;
  business_exposure_factor: number;
};

export type RiskContributorItem = {
  factor: string;
  score: number;
  max_score: number;
  label: string;
  weight_pct: number;
  description?: string;
};

export type BankingRiskAssessment = {
  asset_id: string;
  asset_name: string;
  system_type: string;
  technical_risk: TechnicalRiskContext;
  business_context: BusinessRiskContext;
  key_protection: KeyChainAnalysis;
  migration_priority: MigrationPriority;
  priority_score: number;
  priority_band_label: string;
  contributors: RiskContributorItem[];
  explanation: string;
  recommended_planning_window: string;
  created_at?: string;
};

export type UpgradeScoreBreakdown = {
  governing_technical_risk: number;
  technical_risk_factor: number;
  criticality_score: number;
  sensitivity_score: number;
  lifetime_score: number;
  exposure_score: number;
  migration_effort_score: number;
  business_exposure_factor: number;
  migration_effort_factor: number;
  composite_urgency_factor: number;
};

export type RankedUpgradeItem = {
  rank: number;
  system_id: string;
  system_name: string;
  system: string;
  priority: MigrationPriority;
  priority_score: number;
  quantum_score: number;
  classical_score: number;
  score_breakdown: UpgradeScoreBreakdown;
  criticality: string;
  sensitivity: string;
  data_lifetime: string;
  lifetime: string;
  exposure: string;
  migration_impact: string;
  top_findings: string[];
  key_protection_chain: Record<string, string>;
  crypto_agility: string;
  evidence_gaps: string[];
  recommended_migration: string;
  recommended_upgrade: string;
  migration_complexity: string;
  estimated_migration_complexity: string;
};

export type RankedUpgradePlan = {
  timestamp: string;
  total_systems: number;
  p0_count: number;
  p1_count: number;
  p2_count: number;
  p3_count: number;
  queue: RankedUpgradeItem[];
};

export type ScanResponse = {
  target: TargetInfo;
  scan_status: string;
  certificate: CertificateInfo;
  tls: TlsInfo;
  cryptography: NormalizedCryptoMechanism[];
  findings: QuantumFinding[];
  score: QuantumScore;
  role_assessments: RoleCategoryAssessment[];
  executive_summary: ExecutiveSummary;
  migration_plan: MigrationStep[];
  observability_scope: ObservabilityScope;
  not_observable_notes: string[];
  banking_asset?: BankingAsset;
  banking_risk?: BankingRiskAssessment;
  audit_findings?: AuditFinding[];
  zero_trust?: ZeroTrustAssessment;
};

export type ApiError = {
  error: string;
  detail: string;
  target_domain?: string;
};


export type NormalizedFinding = {
  rule_id: string;
  title: string;
  value: string;
  role: string;
  source: string;
  source_file?: string | null;
  source_line?: number | null;
  evidence_status: string;
  severity: string;
  risk: string;
  message: string;
  recommendation: string;
  system_id?: string | null;
  asset_id?: string | null;
  layer?: string | null;
  metadata: Record<string, unknown>;
};

export type ArtifactFindingsResponse = {
  scan_status: 'SUCCESS';
  files_scanned: number;
  finding_count: number;
  findings: NormalizedFinding[];
};

export type UploadedCertificateInfo = {
  subject_cn: string | null;
  subject_org: string | null;
  subject_alt_names: string[];
  issuer_cn: string | null;
  issuer_org: string | null;
  serial_number: string;
  fingerprint_sha256: string;
  not_valid_before: string;
  not_valid_after: string;
  days_remaining: number;
  is_expired: boolean;
  public_key_algorithm: string;
  key_size_bits: number | null;
  curve_name: string | null;
  signature_algorithm: string;
  signature_hash_algorithm: string | null;
};

export type UploadedCertificateResponse = {
  scan_status: 'SUCCESS';
  source: 'UPLOADED_CERTIFICATE';
  source_file: string;
  evidence_status: 'OBSERVED';
  certificate: UploadedCertificateInfo;
};

// ==============================================================================
// PHASE 4C: WHAT-IF POST-QUANTUM MIGRATION SIMULATOR TYPES
// ==============================================================================

export type MigrationComponent =
  | 'KEY_WRAPPING'
  | 'AUTHENTICATION'
  | 'TLS_PROTOCOL'
  | 'TLS_KEY_EXCHANGE';

export type MigrationAction = {
  component: MigrationComponent;
  current_algorithm?: string;
  target_algorithm: string;
  description?: string;
};

export type WhatIfMigrationComparison = {
  priority_score_before: number;
  priority_score_after: number;
  priority_score_delta: number;
  risk_reduction: number;
  priority_band_before: MigrationPriority;
  priority_band_after: MigrationPriority;
  priority_transition: string;
  key_chain_status_before: KeyChainStatus;
  key_chain_status_after: KeyChainStatus;
  key_chain_transition: string;
  technical_risk_before: TechnicalRiskContext;
  technical_risk_after: TechnicalRiskContext;
  weak_links_before: string[];
  weak_links_after: string[];
  resolved_findings: string[];
  remaining_findings: string[];
  newly_introduced_findings?: string[];
};

export type WhatIfMigrationRequest = {
  asset_id?: string;
  asset?: BankingAsset;
  scan_quantum_score?: number;
  changes: MigrationAction[];
};

export type WhatIfMigrationResult = {
  simulation_id: string;
  asset_id: string;
  asset_name: string;
  evidence_state: string;
  simulation_disclaimer: string;
  operations: MigrationAction[];
  before: BankingRiskAssessment;
  after: BankingRiskAssessment;
  comparison: WhatIfMigrationComparison;
  explanation: string;
  created_at: string;
};

// ==============================================================================
// TASK 5: COMPREHENSIVE REPORT DOWNLOADS & AUDIT VERIFICATION
// ==============================================================================

export type AuditRecord = {
  record_id: string;
  assessment_id: string;
  assessment_hash: string;
  previous_hash: string;
  current_hash: string;
  timestamp: string;
  signature?: string;
  schema_version: string;
  canonical_payload?: string | null;
};

export type AuditVerificationResult = {
  valid: boolean;
  status?: string;
  record_id?: string | null;
  error?: string | null;
  records_checked: number;
  details: Record<string, unknown>;
};

export type AuditLedgerResponse = {
  total: number;
  limit: number;
  offset: number;
  records: AuditRecord[];
};

export type AuditHeadResponse = {
  record_id?: string | null;
  current_hash: string;
  timestamp?: string | null;
  record_count: number;
  chain_valid: boolean;
  status: string;
  checkpoint?: Record<string, unknown> | null;
  external_anchor?: string;
  external_checkpoint?: Record<string, unknown> | null;
};

export type CompleteAssessmentReport = {
  metadata: Record<string, unknown>;
  report_metadata: Record<string, unknown>;
  executive_summary: Record<string, unknown>;
  system: Record<string, unknown>;
  system_metadata: Record<string, unknown>;
  quantum_posture: Record<string, unknown>;
  classical_posture: Record<string, unknown>;
  priority: Record<string, unknown>;
  priority_factors: Record<string, unknown>;
  findings: unknown[];
  key_protection_chain: Record<string, unknown>;
  crypto_agility: Record<string, unknown>;
  migration_impact: Record<string, unknown>;
  ranked_upgrade_plan: RankedUpgradePlan;
  cbom: Record<string, unknown>;
  evidence_gaps: Record<string, unknown>[];
  observability: Record<string, unknown>;
  what_if?: Record<string, unknown> | null;
  what_if_results?: Record<string, unknown> | null;
  audit: AuditRecord;
  audit_metadata: AuditRecord;
  zero_trust?: Record<string, unknown> | null;
  compliance_mappings?: Record<string, unknown> | null;
  ai_advisory?: Record<string, unknown> | null;
};

// ==============================================================================
// TASK 10: AI-POWERED QUANTUM READINESS INTELLIGENCE
// ==============================================================================

export type AIStatus = {
  is_available: boolean;
  provider: string;
  model?: string | null;
  message: string;
};

export type AIExplanationResult<T> = {
  success: boolean;
  is_available: boolean;
  provider: string;
  data?: T | null;
  error?: string | null;
  disclaimer: string;
  evidence_hash?: string | null;
};

export type FindingExplanationRequest = {
  rule_id: string;
  title: string;
  value: string;
  role: string;
  source: string;
  evidence_status: string;
  severity: string;
  risk: string;
  message?: string;
  recommendation?: string;
  system_id?: string;
  asset_id?: string;
};

export type FindingExplanationResponse = {
  rule_id: string;
  meaning: string;
  why_it_matters: string;
  quantum_relevance: string;
  crypto_component: string;
  what_evidence_establishes: string;
  what_evidence_does_not_establish: string;
  banking_impact: string;
  remediation: string;
  migration_considerations: string;
  standards_guidance: string;
  advisory_disclaimer: string;
  evidence_hash?: string | null;
  evidence_status?: string | null;
  generated_at?: string | null;
  provenance_verified?: boolean | null;
};

export type BankingRiskExplanationRequest = {
  system_id: string;
  system_name: string;
  priority_score: number;
  priority_band: string;
  quantum_risk_level?: string;
  classical_risk_level?: string;
  criticality?: string;
  data_sensitivity?: string;
  data_lifetime?: string;
  exposure?: string;
  migration_effort?: string;
  top_findings?: string[];
  weak_links?: string[];
  evidence_gaps?: string[];
};

export type BankingRiskExplanationResponse = {
  system_id: string;
  system_name: string;
  score_rationale: string;
  contributing_factors: string[];
  severity_weighting_explanation: string;
  upgrade_queue_position_reason: string;
  supporting_evidence: string[];
  evidence_gaps_needed: string[];
  advisory_disclaimer: string;
  evidence_hash?: string | null;
  evidence_status?: string | null;
  generated_at?: string | null;
  provenance_verified?: boolean | null;
};

export type MigrationAdvisoryRequest = {
  system_id: string;
  system_name: string;
  baseline_priority_score: number;
  baseline_priority_band: string;
  target_replacement?: string;
  simulated_changes?: Array<Record<string, unknown>>;
  projected_priority_score?: number;
  projected_priority_band?: string;
  crypto_agility?: string;
  migration_impact?: string;
  dependencies?: string[];
};

export type MigrationAdvisoryResponse = {
  system_id: string;
  system_name: string;
  migration_justification: string;
  target_cryptographic_roles: string[];
  pqc_direction: string;
  operational_impact_assessment: string;
  interoperability_and_testing: string;
  suggested_migration_phases: string[];
  pre_deployment_validation_steps: string[];
  advisory_disclaimer: string;
  evidence_hash?: string | null;
  evidence_status?: string | null;
  generated_at?: string | null;
  provenance_verified?: boolean | null;
};

export type ReportExplanationRequest = {
  system_id: string;
};

export type ReportExplanationResponse = {
  system_id: string;
  executive_summary: {
    overall_situation: string;
    primary_risks: string;
    critical_assets: string;
    high_level_actions: string;
  };
  technical_summary: {
    cryptographic_findings: string;
    evidence_distinctions: string;
    algorithm_migration: string;
    dependencies: string;
    sequence: string;
  };
  management_recommendations: {
    prioritization_rationale: string;
    migration_planning: string;
    governance_and_validation: string;
  };
  advisory_disclaimer: string;
  evidence_hash?: string | null;
  evidence_status?: string | null;
  generated_at?: string | null;
  provenance_verified?: boolean | null;
};

export type AIBudgetTelemetry = {
  date: string;
  daily_token_budget: number;
  tokens_used_today: number;
  tokens_remaining: number;
  daily_cost_budget_usd: number;
  cost_used_today_usd: number;
  cost_remaining_usd: number;
  is_budget_exceeded: boolean;
  resets_at: string;
  is_budget_exhausted?: boolean;
  current_date?: string;
  reset_at?: string;
};

// ==============================================================================
// PHASE F: CYCLONEDX 1.7 CBOM (CRYPTOGRAPHIC BILL OF MATERIALS) TYPES
// ==============================================================================

export type CBOMProperty = {
  name: string;
  value: string;
};

export type CBOMAlgorithmProperties = {
  primitive?: string;
  parameterSetIdentifier?: string;
  curve?: string;
  executionEnvironment?: string;
  implementationPlatform?: string;
  certificationLevel?: string;
  mode?: string;
  padding?: string;
  cryptoFunctions?: string[];
  classicalSecurityLevel?: number;
  nistQuantumSecurityLevel?: number;
};

export type CBOMCryptoProperties = {
  assetType: 'algorithm' | 'certificate' | 'protocol' | 'related-crypto-material' | string;
  algorithmProperties?: CBOMAlgorithmProperties;
  certificateProperties?: Record<string, unknown>;
  protocolProperties?: Record<string, unknown>;
  relatedCryptoMaterialProperties?: Record<string, unknown>;
  oid?: string;
};

export type CBOMComponent = {
  type: string;
  'bom-ref': string;
  name: string;
  description?: string;
  cryptoProperties: CBOMCryptoProperties;
  properties?: CBOMProperty[];
};

export type CBOMDependency = {
  ref: string;
  dependsOn: string[];
};

export type CBOMDocument = {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata?: {
    timestamp: string;
    tools?: Array<{ vendor?: string; name?: string; version?: string }>;
    component?: Record<string, unknown>;
    properties?: CBOMProperty[];
  };
  components: CBOMComponent[];
  dependencies?: CBOMDependency[];
};
