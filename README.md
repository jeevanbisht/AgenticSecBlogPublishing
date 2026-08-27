# Agentic Security Intelligence

Evidence-driven intelligence on enterprise security agents: what they can do, how autonomous
they are, how they are controlled, what evidence supports each claim, and how those properties
change over time.

This repository implements the evidence ledger, Gate B amendments, human-gated change
intelligence, a durable production API/worker runtime, deterministic public projection,
draft-only downstream publishing, and a static Astro publication for Cloudflare Pages.
Automation prepares drafts; it cannot merge or approve them.

## Architecture and trust model

The durable chain is:

`Vendor → System → Agent → Capability/Control → Assertion → Evidence → Snapshot`

`Model + Harness + Tools + Benchmark` is the identity of a benchmark result. Assertions use
versioned ontology keys rather than sentence hashes, so paraphrases become observations instead
of new claims. Availability history is append-only and evidence-backed. Article and Trend are
segregated output entities; evidence foreign keys can target only `Source` and `Snapshot`, and
assertion evidence links accept only `EV-*` IDs.

Internet content is untrusted. The collection layer uses an approved source registry, domain
allowlists, URL canonicalization, robots-policy injection, rate and size limits, content-type
checks, bounded retries, caching, versioned normalization, hashing, and private snapshots.
Docs-as-git retrieval records repository, commit, file, and line anchors and never executes
downloaded code. Agents cannot approve sources or taxonomy terms.

## Pass 1 contents

- Python 3.12+ package with strict Pydantic domain models
- ASI-1.0 methodology and ASI-TAXONOMY-1.1 controlled vocabularies
- governed seed-source registry, including two non-Microsoft systems
- bounded HTTP and docs-as-git retrieval abstractions
- deterministic `norm-1.0` normalization and SHA-256 snapshots
- exact offset and git-line evidence-anchor validation
- ontology-key assertion identity, dedup observations, scope, and state semantics
- support-confidence, independence, autonomy, and evidence-panel derivations needed at Gate A
- SQLite DDL and typed repositories with structural output/evidence segregation
- Gate A amendment fixtures plus Gate B golden change/conflict fixtures
- CLI, prompt contracts, documentation, and tests

## Pass 2 intelligence and editorial

- deterministic stored-normalized snapshot diffs with chrome, cosmetic, paraphrase, and derivative
  filtering
- structured capability, control, autonomy, approval, permission, trigger, lifecycle, benchmark,
  architecture, model, and agent change classifications
- human review queue for materiality and required human-confirmed decision-impact tags
- rule-based contradiction flags and a separate human resolution queue; no LLM adjudication
- derived freshness (`freshness-1.0`) and deterministic trend primitives
- daily briefs, including the valid no-material-change outcome
- weekly ledger-derived evidence packs with human-authored interpretation boundaries
- claim verification and LOW/MEDIUM/HIGH editorial-risk enforcement

Gate B adds first-class `EVIDENCE_STATUS_CHANGE` classification, exact daily status semantics,
and append-only human review history. See `docs/GATE_B_AMENDMENT_DIFF.md`.

## Production runtime and site

- deterministic SQLite-backed `pipeline daily` and `pipeline weekly` commands with explicit demo mode
- transactional SQLite job queue, restart recovery, worker heartbeat, and single-pipeline lease
- mTLS-bound FastAPI status, job, and review-pending endpoints
- opt-in bounded live HTTP collection for exact approved source IDs, with fail-closed robots policy,
  private persistent cache/snapshots, and no automatic claim or evidence derivation
- deterministic public bundle with private-field scanning and path-sorted content hashes
- real draft-only downstream GitHub publisher with artifact-hash deduplication
- model and GitHub provider abstractions with deterministic mocks
- CI, content validation, and publication-build workflows only; live scheduling runs on sec1
- Astro system profiles, claims-vs-reality, decision-impact change feed, daily archive, weekly
  archive, methodology, RSS/Atom, sitemap, canonical/OpenGraph metadata, and client-side filtering
- static Cloudflare Pages configuration and security headers; no Workers or Astro adapter

## Local setup

```console
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\agentic-security sources validate
.venv\Scripts\agentic-security validate-fixtures
```

The package supports Python 3.12 and newer. No API key is required. `collect` is dry-run only until
Gate A approval:

```console
agentic-security collect --dry-run
agentic-security gate-a --output data\demo\gate_a.json
agentic-security derive
agentic-security init-db --path data\asi.db
agentic-security init-db --path data\demo.db --with-demo
```

Without `--with-demo`, `init-db` seeds only authoritative ASI-1.0 methodology and taxonomy
metadata (including the ASI-TAXONOMY-1.0 → 1.1 dependency chain). It creates no systems, sources,
snapshots, evidence, assertions, or publication claims.

Other useful commands: `sources list`, `taxonomy`, `assertions`, `systems`, and
`lifecycle project-perception`, `changes --dry-run`, `review --dry-run`,
`contradictions --dry-run`, `trends`, `daily --dry-run`, `weekly-pack --dry-run`,
`pipeline daily --dry-run`, `pipeline weekly --dry-run`, `publication export`, and
`publication validate`.
The pipeline and site-export commands read `database_path` from `config/settings.yaml` by default
or accept `--database`. They fail if that ledger is absent or uninitialized. Synthetic runs must
opt in with `--demo`. All mutating commands support dry-run.

## Configuration and governance

- `config/settings.yaml`: methodology, normalizer, storage, retrieval, and cost limits
- `config/sources.yaml`: approved sources, allowed claim types, cadence, and fallback notes
- `config/taxonomy/ASI-TAXONOMY-1.1.yaml`: controlled ontology and autonomy-gate vocabulary

New domains start as `PROPOSED`; an agent cannot enable them. Vocabulary additions are proposed for
human review and cannot be minted during extraction. A rename/split requires a new taxonomy file
and explicit old-to-new mappings.

## Data and workflows

Raw snapshots live under `research/snapshots/` and remain private. The publication-safe unit is a
bounded evidence quote with attribution. `data/demo/gate_a.json` is synthetic fixture data, not a
collected ledger. Production Astro commands validate `publication/` and never open SQLite;
fixture generation remains explicit through the `:demo` scripts.

Daily/weekly intelligence is implemented as deterministic local artifacts. GitHub is the
editorial control plane: agents may prepare drafts, but human-approved merge to `publication` is
the publication boundary. `scripts/generate_site_data.py` reads the configured SQLite ledger by
default. A committed synthetic input must be selected intentionally with
`--demo-input data\demo`; pages do not invent capability ratings or silently fall back
to fixtures.

## Testing

```console
make format
make lint
make typecheck
make test
make check
cd site
npm ci
npm run check:demo
npm test
npm run build:demo
```

Use `npm run check` and `npm run build` to validate the public production bundle.

See `docs/GATE_A_AMENDMENT_DIFF.md`, `docs/GATE_B_AMENDMENT_DIFF.md`,
`docs/GATE_B_REVIEW_PACKET.md`, `METHODOLOGY.md`, and `docs/DEPLOYMENT.md`.
Adding systems or sources requires fixtures/tests, source-purpose policy review, and exact anchors.
Production runtime documents begin with `docs/SECURITY_MODEL.md`,
`docs/PUBLICATION_ARCHITECTURE.md`, and `docs/OPERATIONS.md`.

## Cost controls and roadmap

Deterministic filtering precedes model use. Source, model-call, input-size, and output limits are
in `config/settings.yaml`.
EvaluatorEngagement normalization, LLM trend inference/adjudication, autonomous materiality,
practitioner evidence intake, and dedicated browse UIs remain V2+ deferrals.
