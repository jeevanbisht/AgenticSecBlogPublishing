export type Change = {
  id: string;
  classification: string;
  date: string | null;
  decision_impacts: string[];
  description: string;
};

export type Article = {
  id: string;
  title: string;
  body: string;
};

export type Conflict = {
  type: string;
  rationale: string;
};

export type EvidencePanel = {
  vendor_documentation: string;
  public_demonstration: string;
  independent_validation: string;
  production_effectiveness: string;
  methodology_version: string;
  rationale: string;
};

export type Capability = {
  name: string;
  statement: string;
  state: string;
  scope: { conditions: string[] };
  evidence_panel: EvidencePanel;
  support_confidence: {
    value: string;
    methodology_version: string;
    rationale: string;
  };
};

export type SystemProfile = {
  id: string;
  name: string;
  vendor: string;
  category: string;
  description: string;
  first_observed_at: string;
  last_verified_at: string;
  freshness: string;
  methodology_version: string;
  taxonomy_version: string;
  lifecycle: {
    state: string;
    effective_at: string;
    evidence_id: string;
    conditions: string[];
    regions: string[];
  }[];
  agents: {
    category: string;
    name: string;
    description: string;
    capabilities: string[];
    controls: string[];
  }[];
  autonomy: {
    derived_label: string;
    trigger: { value: string };
    persistence: { value: string };
    permission_scope: { value: string };
    human_gate: { value: string };
  } | null;
  controls: { statement: string; state: string }[];
  architecture: { statement: string; state: string }[];
  capabilities: Capability[];
  conflicts: Conflict[];
  recent_changes: Change[];
  sources: { id: string; publisher: string; name: string }[];
};

export type Claim = {
  system_id: string;
  system_name: string;
  capability: string;
  vendor_claims: string;
  primary_documentation: string;
  demonstrated: string;
  benchmarked: string;
  independently_validated: string;
  unknown: string;
};

export type LedgerData = {
  generated_at: string;
  canonical_base: string;
  methodology_version: string;
  taxonomy_version: string;
  systems: SystemProfile[];
  claims: Claim[];
  changes: Change[];
  articles: Article[];
  daily: { date: string; status: string; markdown: string }[];
  weekly: { date: string; markdown: string }[];
  sources: {
    id: string;
    publisher: string;
    name: string;
    role: string;
    contributes_evidence: boolean;
  }[];
};
