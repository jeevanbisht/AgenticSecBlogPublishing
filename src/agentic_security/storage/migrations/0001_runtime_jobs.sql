CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    job_type TEXT NOT NULL CHECK (
        job_type IN (
            'COLLECT',
            'RESEARCH',
            'DAILY',
            'WEEKLY_PACK',
            'PUBLICATION_EXPORT',
            'PUBLICATION_PR'
        )
    ),
    requested_by TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    queued_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    updated_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('QUEUED','RUNNING','SUCCEEDED','FAILED','CANCELLED')
    ),
    retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    failure_category TEXT,
    sanitized_failure_message TEXT
);

CREATE INDEX IF NOT EXISTS jobs_status_created_idx
ON jobs(status, created_at, job_id);

CREATE TABLE IF NOT EXISTS pipeline_leases (
    name TEXT PRIMARY KEY,
    holder_id TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS worker_heartbeats (
    worker_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL
);
