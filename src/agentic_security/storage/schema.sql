PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS methodology_versions (
    id TEXT PRIMARY KEY CHECK (id GLOB 'ASI-[0-9]*.[0-9]*'),
    published_at TEXT NOT NULL,
    description TEXT NOT NULL,
    normalizer_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS taxonomy_versions (
    id TEXT PRIMARY KEY,
    published_at TEXT NOT NULL,
    previous_version TEXT REFERENCES taxonomy_versions(id),
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vendors (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, website TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS systems (
    id TEXT PRIMARY KEY,
    vendor_id TEXT NOT NULL REFERENCES vendors(id),
    name TEXT NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL,
    first_observed_at TEXT NOT NULL, last_verified_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    system_id TEXT NOT NULL REFERENCES systems(id),
    name TEXT NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL,
    first_observed_at TEXT NOT NULL, last_verified_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capabilities (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL,
    taxonomy_version TEXT NOT NULL REFERENCES taxonomy_versions(id)
);
CREATE TABLE IF NOT EXISTS controls (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL,
    taxonomy_version TEXT NOT NULL REFERENCES taxonomy_versions(id)
);
CREATE TABLE IF NOT EXISTS architecture_patterns (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL,
    taxonomy_version TEXT NOT NULL REFERENCES taxonomy_versions(id)
);
CREATE TABLE IF NOT EXISTS models (
    id TEXT PRIMARY KEY, provider TEXT NOT NULL, name TEXT NOT NULL, version TEXT
);
CREATE TABLE IF NOT EXISTS harnesses (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, version TEXT, repository_url TEXT
);
CREATE TABLE IF NOT EXISTS benchmarks (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, version TEXT NOT NULL,
    task_definition TEXT NOT NULL, success_criterion TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY CHECK (id LIKE 'SRC-%'),
    publisher TEXT NOT NULL, name TEXT NOT NULL, kind TEXT NOT NULL,
    trust_class TEXT NOT NULL, status TEXT NOT NULL, enabled INTEGER NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS source_provenance (
    source_id TEXT NOT NULL REFERENCES sources(id),
    derivative_of_source_id TEXT NOT NULL REFERENCES sources(id),
    rationale TEXT NOT NULL,
    PRIMARY KEY (source_id, derivative_of_source_id),
    CHECK (source_id <> derivative_of_source_id)
);
CREATE TABLE IF NOT EXISTS snapshots (
    id TEXT PRIMARY KEY CHECK (id LIKE 'SNAP-%'),
    source_id TEXT NOT NULL REFERENCES sources(id),
    canonical_uri TEXT NOT NULL, retrieved_at TEXT NOT NULL,
    normalizer_version TEXT NOT NULL, sha256 TEXT NOT NULL,
    content_type TEXT NOT NULL, raw_content TEXT NOT NULL, normalized_text TEXT NOT NULL,
    duplicate_of TEXT REFERENCES snapshots(id),
    repository TEXT, commit_sha TEXT, file_path TEXT,
    UNIQUE(source_id, canonical_uri, sha256)
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY CHECK (id LIKE 'EV-%'),
    source_id TEXT NOT NULL REFERENCES sources(id),
    snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
    source_class TEXT NOT NULL, maturity TEXT NOT NULL,
    claim_purpose TEXT NOT NULL,
    derivative_of_evidence_id TEXT REFERENCES evidence(id),
    payload_json TEXT NOT NULL,
    CHECK (source_id NOT LIKE 'ARTICLE-%' AND source_id NOT LIKE 'TREND-%'),
    CHECK (snapshot_id NOT LIKE 'ARTICLE-%' AND snapshot_id NOT LIKE 'TREND-%')
);
CREATE TABLE IF NOT EXISTS assertions (
    id TEXT PRIMARY KEY CHECK (id LIKE 'ASRT-%'),
    assertion_key TEXT NOT NULL UNIQUE,
    taxonomy_version TEXT NOT NULL REFERENCES taxonomy_versions(id),
    system_id TEXT NOT NULL REFERENCES systems(id),
    agent_id TEXT REFERENCES agents(id),
    state TEXT NOT NULL, statement TEXT NOT NULL,
    published_at TEXT, modified_at TEXT, first_seen_at TEXT NOT NULL,
    retrieved_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
    last_verified_at TEXT NOT NULL, effective_at TEXT,
    superseded_by TEXT REFERENCES assertions(id),
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assertion_evidence (
    assertion_id TEXT NOT NULL REFERENCES assertions(id),
    evidence_id TEXT NOT NULL REFERENCES evidence(id)
      CHECK (evidence_id LIKE 'EV-%'
             AND evidence_id NOT LIKE 'ARTICLE-%'
             AND evidence_id NOT LIKE 'TREND-%'),
    relation TEXT NOT NULL CHECK (relation IN ('SUPPORTS', 'CONTRADICTS')),
    PRIMARY KEY (assertion_id, evidence_id, relation)
);
CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY CHECK (id LIKE 'OBS-%'),
    assertion_id TEXT NOT NULL REFERENCES assertions(id),
    evidence_id TEXT NOT NULL REFERENCES evidence(id),
    observed_statement TEXT NOT NULL, observed_at TEXT NOT NULL, published_at TEXT,
    modified_at TEXT, first_seen_at TEXT NOT NULL, retrieved_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL, last_verified_at TEXT NOT NULL, effective_at TEXT,
    is_paraphrase INTEGER NOT NULL, accepted INTEGER NOT NULL, scope_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS lifecycle_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    system_id TEXT REFERENCES systems(id),
    agent_id TEXT REFERENCES agents(id),
    state TEXT NOT NULL, modifiers_json TEXT NOT NULL, effective_at TEXT,
    evidence_id TEXT NOT NULL REFERENCES evidence(id),
    source_class TEXT NOT NULL, retrieved_at TEXT NOT NULL, rationale TEXT NOT NULL,
    CHECK ((system_id IS NULL) != (agent_id IS NULL))
);
CREATE TRIGGER IF NOT EXISTS lifecycle_events_no_update
BEFORE UPDATE ON lifecycle_events BEGIN SELECT RAISE(ABORT, 'lifecycle history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS lifecycle_events_no_delete
BEFORE DELETE ON lifecycle_events BEGIN SELECT RAISE(ABORT, 'lifecycle history is append-only'); END;
CREATE TABLE IF NOT EXISTS autonomy_assessments (
    id TEXT PRIMARY KEY, system_id TEXT NOT NULL REFERENCES systems(id),
    agent_id TEXT REFERENCES agents(id), payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS benchmark_results (
    id TEXT PRIMARY KEY, benchmark_id TEXT NOT NULL REFERENCES benchmarks(id),
    model_id TEXT NOT NULL REFERENCES models(id),
    harness_id TEXT NOT NULL REFERENCES harnesses(id),
    evidence_id TEXT NOT NULL REFERENCES evidence(id), payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS material_change_examples (
    id TEXT PRIMARY KEY, payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS structured_diffs (
    id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES sources(id),
    old_snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
    new_snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
    material_candidate INTEGER NOT NULL, payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS change_review_queue (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES structured_diffs(id),
    prior_review_id TEXT REFERENCES change_review_queue(id),
    machine_classification TEXT NOT NULL,
    machine_rationale TEXT NOT NULL,
    machine_decision_impacts_json TEXT NOT NULL,
    evidence_status_subtype TEXT,
    status TEXT NOT NULL,
    reviewer TEXT,
    reviewed_at TEXT,
    human_classification TEXT,
    confirmed_decision_impacts_json TEXT NOT NULL,
    human_rationale TEXT,
    methodology_version TEXT NOT NULL REFERENCES methodology_versions(id),
    payload_json TEXT NOT NULL,
    CHECK (
      (machine_classification = 'EVIDENCE_STATUS_CHANGE' AND evidence_status_subtype IS NOT NULL)
      OR
      (machine_classification <> 'EVIDENCE_STATUS_CHANGE' AND evidence_status_subtype IS NULL)
    ),
    CHECK (
      (status = 'PENDING' AND reviewer IS NULL AND reviewed_at IS NULL
       AND human_classification IS NULL AND human_rationale IS NULL AND prior_review_id IS NULL)
      OR
      (status <> 'PENDING' AND reviewer IS NOT NULL AND reviewed_at IS NOT NULL
       AND human_classification IS NOT NULL AND human_rationale IS NOT NULL
       AND prior_review_id IS NOT NULL)
    )
);
CREATE TRIGGER IF NOT EXISTS change_review_queue_no_update
BEFORE UPDATE ON change_review_queue
BEGIN SELECT RAISE(ABORT, 'human review history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS change_review_queue_no_delete
BEFORE DELETE ON change_review_queue
BEGIN SELECT RAISE(ABORT, 'human review history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS change_review_queue_preserve_machine_proposal
BEFORE INSERT ON change_review_queue
WHEN NEW.prior_review_id IS NOT NULL
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM change_review_queue prior
    WHERE prior.id = NEW.prior_review_id
      AND prior.candidate_id = NEW.candidate_id
      AND prior.machine_classification = NEW.machine_classification
      AND prior.machine_rationale = NEW.machine_rationale
      AND prior.machine_decision_impacts_json = NEW.machine_decision_impacts_json
      AND COALESCE(prior.evidence_status_subtype, '') =
          COALESCE(NEW.evidence_status_subtype, '')
      AND prior.methodology_version = NEW.methodology_version
  ) THEN RAISE(ABORT, 'machine proposal is immutable across review history') END;
END;
CREATE UNIQUE INDEX IF NOT EXISTS one_machine_proposal_per_candidate
ON change_review_queue(candidate_id)
WHERE prior_review_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS one_successor_per_review
ON change_review_queue(prior_review_id)
WHERE prior_review_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS confirmed_changes (
    id TEXT PRIMARY KEY, review_id TEXT NOT NULL REFERENCES change_review_queue(id),
    confirmed_at TEXT NOT NULL, payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS contradiction_flags (
    id TEXT PRIMARY KEY, status TEXT NOT NULL, payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS contradiction_resolutions (
    id TEXT PRIMARY KEY, conflict_id TEXT NOT NULL REFERENCES contradiction_flags(id),
    reviewed_at TEXT NOT NULL, payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS output_articles (
    id TEXT PRIMARY KEY CHECK (id LIKE 'ARTICLE-%'), payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS output_trends (
    id TEXT PRIMARY KEY CHECK (id LIKE 'TREND-%'), payload_json TEXT NOT NULL
);
