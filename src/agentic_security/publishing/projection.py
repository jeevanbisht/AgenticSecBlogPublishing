"""Deterministic ledger-to-publication projection."""

from __future__ import annotations

import json
import shutil
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

from agentic_security.publishing.validation import (
    PublicationManifest,
    file_hash,
    validate_publication_bundle,
)
from agentic_security.runtime import RuntimeConfig
from agentic_security.site_data import build_site_data
from agentic_security.storage.database import configure_connection
from agentic_security.storage.read_models import PublicationLedgerData, read_publication_ledger


def _semantic_as_of(data: PublicationLedgerData) -> datetime:
    values = [
        *(item.last_verified_at for item in data.systems),
        *(item.last_verified_at for item in data.assertions),
        *(item.last_verified_at for item in data.evidence),
        *(item.confirmed_at for item in data.confirmed_changes if item.confirmed_at is not None),
        *(
            item.reviewed_at
            for item in data.latest_review_decisions
            if item.reviewed_at is not None
        ),
    ]
    return max(values) if values else data.methodology_published_at


def source_ledger_version(database_path: Path) -> str:
    connection = configure_connection(
        sqlite3.connect(
            f"file:{database_path.as_posix()}?mode=ro",
            uri=True,
            timeout=5,
        ),
        enable_wal=False,
    )
    try:
        table = connection.execute(
            """SELECT 1 FROM sqlite_master
               WHERE type='table' AND name='schema_migrations'"""
        ).fetchone()
        if table is None:
            return "sqlite-legacy-0"
        row = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1"
        ).fetchone()
        return f"sqlite-schema-{int(row[0]) if row is not None else 0}"
    finally:
        connection.close()


class PublicationProjectionService:
    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config

    def export(
        self,
        *,
        output_root: Path | None = None,
        generated_at: datetime | None = None,
    ) -> PublicationManifest:
        target = output_root or self.config.export_path
        data = read_publication_ledger(
            self.config.database_path,
            settings_path=self.config.settings_path,
        )
        semantic_as_of = _semantic_as_of(data)
        payload = build_site_data(
            ledger_data=data,
            generated_at=semantic_as_of,
            semantic_as_of=semantic_as_of,
            canonical_base=str(self.config.canonical_base),
        )
        parent = target.parent
        parent.mkdir(parents=True, exist_ok=True)
        stage = parent / f".{target.name}.stage-{uuid.uuid4().hex}"
        backup = parent / f".{target.name}.backup-{uuid.uuid4().hex}"
        try:
            data_path = stage / "data" / "ledger.json"
            data_path.parent.mkdir(parents=True, exist_ok=True)
            data_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            hashes = tuple(
                file_hash(path, relative_to=stage)
                for path in sorted(stage.rglob("*"))
                if path.is_file()
            )
            manifest = PublicationManifest(
                generated_at=generated_at or datetime.now(UTC),
                methodology_version=data.methodology_version,
                taxonomy_version=data.taxonomy_version,
                source_ledger_version=source_ledger_version(self.config.database_path),
                content_count=len(payload["systems"]) + len(payload["changes"]),
                confirmed_change_count=len(payload["changes"]),
                pending_review_count=sum(
                    item.status.value == "PENDING" for item in data.latest_review_decisions
                ),
                files=hashes,
            )
            (stage / "manifest.json").write_text(
                json.dumps(manifest.model_dump(mode="json"), indent=2) + "\n",
                encoding="utf-8",
            )
            validate_publication_bundle(stage)
            if target.exists():
                target.rename(backup)
            stage.rename(target)
            if backup.exists():
                shutil.rmtree(backup)
            return validate_publication_bundle(target)
        except Exception:
            if stage.exists():
                shutil.rmtree(stage)
            if backup.exists() and not target.exists():
                backup.rename(target)
            raise
