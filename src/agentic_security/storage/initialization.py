"""Authoritative production ledger metadata initialization."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from agentic_security.models import MethodologyVersion, TaxonomyVersion
from agentic_security.storage.database import Database
from agentic_security.taxonomy import load_taxonomy

ROOT = Path(__file__).resolve().parents[3]
SETTINGS_PATH = ROOT / "config" / "settings.yaml"


@dataclass(frozen=True)
class AuthoritativeMetadata:
    methodology: MethodologyVersion
    taxonomies: tuple[TaxonomyVersion, ...]

    @property
    def current_taxonomy(self) -> TaxonomyVersion:
        return self.taxonomies[-1]


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def _taxonomy_payload(taxonomy: TaxonomyVersion) -> str:
    return json.dumps(
        taxonomy.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )


def load_authoritative_metadata(
    settings_path: Path = SETTINGS_PATH,
) -> AuthoritativeMetadata:
    root = settings_path.resolve().parents[1]
    settings: dict[str, Any] = yaml.safe_load(settings_path.read_text(encoding="utf-8"))
    methodology_path = _resolve(root, str(settings["methodology_file"]))
    methodology_raw: dict[str, Any] = yaml.safe_load(methodology_path.read_text(encoding="utf-8"))
    methodology_id = str(methodology_raw["methodology_version"])
    if methodology_id != str(settings["methodology_version"]):
        raise ValueError("configured methodology version does not match its authoritative YAML")
    normalizer_version = str(settings["normalizer_version"])
    if str(methodology_raw["normalizer_version"]) != normalizer_version:
        raise ValueError("configured normalizer version does not match methodology YAML")
    description = f"Authoritative methodology metadata for {methodology_id}."
    if len(description) > 160 or any(character in description for character in "\r\n"):
        raise ValueError("methodology description is not publication-safe")
    methodology = MethodologyVersion(
        id=methodology_id,
        published_at=methodology_raw["published_at"],
        description=description,
        normalizer_version=normalizer_version,
    )

    configured_taxonomy_path = _resolve(root, str(settings["taxonomy_file"]))
    configured_taxonomy = load_taxonomy(configured_taxonomy_path)
    if methodology_raw.get("taxonomy_version") != configured_taxonomy.id:
        raise ValueError("methodology taxonomy version does not match configured taxonomy")
    chain: list[TaxonomyVersion] = []
    seen: set[str] = set()
    current = configured_taxonomy
    while True:
        if current.id in seen:
            raise ValueError("taxonomy dependency cycle detected")
        seen.add(current.id)
        chain.append(current)
        if current.previous_version is None:
            break
        dependency_path = configured_taxonomy_path.with_name(f"{current.previous_version}.yaml")
        dependency = load_taxonomy(dependency_path)
        if dependency.id != current.previous_version:
            raise ValueError("taxonomy dependency file has the wrong version")
        current = dependency
    chain.reverse()
    return AuthoritativeMetadata(methodology=methodology, taxonomies=tuple(chain))


def _apply_authoritative_metadata(
    connection: sqlite3.Connection,
    metadata: AuthoritativeMetadata,
    *,
    insert_missing: bool,
) -> None:
    expected_taxonomies = {item.id: item for item in metadata.taxonomies}
    existing_taxonomy_ids = {
        str(row[0]) for row in connection.execute("SELECT id FROM taxonomy_versions").fetchall()
    }
    unexpected_taxonomies = existing_taxonomy_ids - set(expected_taxonomies)
    if unexpected_taxonomies:
        raise ValueError(
            f"ledger contains unexpected taxonomy metadata: {sorted(unexpected_taxonomies)}"
        )
    for taxonomy in metadata.taxonomies:
        expected = (
            taxonomy.published_at.isoformat(),
            taxonomy.previous_version,
            _taxonomy_payload(taxonomy),
        )
        row = connection.execute(
            """SELECT published_at,previous_version,payload_json
               FROM taxonomy_versions WHERE id=?""",
            (taxonomy.id,),
        ).fetchone()
        if row is None:
            if not insert_missing:
                raise ValueError(f"ledger is missing authoritative taxonomy {taxonomy.id}")
            connection.execute(
                """INSERT INTO taxonomy_versions(
                       id,published_at,previous_version,payload_json
                   ) VALUES (?,?,?,?)""",
                (taxonomy.id, *expected),
            )
        elif tuple(row) != expected:
            raise ValueError(f"ledger taxonomy metadata drift detected for {taxonomy.id}")

    methodology = metadata.methodology
    existing_methodology_ids = {
        str(row[0]) for row in connection.execute("SELECT id FROM methodology_versions").fetchall()
    }
    if existing_methodology_ids - {methodology.id}:
        raise ValueError("ledger contains unexpected methodology metadata")
    expected_methodology = (
        methodology.published_at.isoformat(),
        methodology.description,
        methodology.normalizer_version,
    )
    row = connection.execute(
        """SELECT published_at,description,normalizer_version
           FROM methodology_versions WHERE id=?""",
        (methodology.id,),
    ).fetchone()
    if row is None:
        if not insert_missing:
            raise ValueError(f"ledger is missing authoritative methodology {methodology.id}")
        connection.execute(
            """INSERT INTO methodology_versions(
                   id,published_at,description,normalizer_version
               ) VALUES (?,?,?,?)""",
            (methodology.id, *expected_methodology),
        )
    elif tuple(row) != expected_methodology:
        raise ValueError(f"ledger methodology metadata drift detected for {methodology.id}")


def seed_authoritative_metadata(
    connection: sqlite3.Connection,
    metadata: AuthoritativeMetadata | None = None,
) -> AuthoritativeMetadata:
    authoritative = metadata or load_authoritative_metadata()
    _apply_authoritative_metadata(connection, authoritative, insert_missing=True)
    return authoritative


def verify_authoritative_metadata(
    connection: sqlite3.Connection,
    metadata: AuthoritativeMetadata | None = None,
) -> AuthoritativeMetadata:
    authoritative = metadata or load_authoritative_metadata()
    _apply_authoritative_metadata(connection, authoritative, insert_missing=False)
    return authoritative


def initialize_authoritative_ledger(
    path: Path,
    *,
    settings_path: Path = SETTINGS_PATH,
) -> AuthoritativeMetadata:
    path.parent.mkdir(parents=True, exist_ok=True)
    database = Database(path)
    database.initialize()
    metadata = load_authoritative_metadata(settings_path)
    with database.transaction(immediate=True) as connection:
        seed_authoritative_metadata(connection, metadata)
    return metadata
