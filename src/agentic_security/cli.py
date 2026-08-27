"""Pass 1 command-line interface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from agentic_security.derivations import (
    derive_autonomy_label,
    derive_capability_evidence_panel,
    derive_freshness,
    derive_independence,
)
from agentic_security.editorial.reports import build_daily_brief, build_weekly_pack
from agentic_security.evidence.validation import (
    validate_evidence_anchor,
    validate_evidence_classification,
)
from agentic_security.fixtures import NOW, gate_a_packet
from agentic_security.pass2_fixtures import gate_b_fixture
from agentic_security.pipelines import run_daily_pipeline, run_weekly_pipeline
from agentic_security.publishing.github import GitHubDraftPublisher, PublicationError
from agentic_security.publishing.projection import PublicationProjectionService
from agentic_security.publishing.validation import validate_publication_bundle
from agentic_security.runtime import load_runtime_config
from agentic_security.site_data import write_site_data
from agentic_security.sources.registry import SourceRegistry
from agentic_security.storage.database import Database
from agentic_security.storage.initialization import initialize_authoritative_ledger
from agentic_security.storage.repositories import GateAPacketRepository
from agentic_security.taxonomy import load_taxonomy
from agentic_security.trend_primitives.queries import (
    decision_impact_frequency,
    new_agents_by_month,
    preview_to_ga_velocity,
)

app = typer.Typer(help="Agentic Security Intelligence — Gate A amended foundation and Pass 2.")
sources_app = typer.Typer(help="Inspect and validate governed source configuration.")
taxonomy_app = typer.Typer(help="Inspect approved ontology vocabulary.")
assertions_app = typer.Typer(help="Inspect fixture assertion ledger.")
systems_app = typer.Typer(help="Inspect tracked fixture systems.")
pipeline_app = typer.Typer(help="Run SQLite-backed publication pipelines or explicit demos.")
publication_app = typer.Typer(help="Export, validate, and draft-publish public-safe bundles.")
app.add_typer(sources_app, name="sources")
app.add_typer(taxonomy_app, name="taxonomy")
app.add_typer(assertions_app, name="assertions")
app.add_typer(systems_app, name="systems")
app.add_typer(pipeline_app, name="pipeline")
app.add_typer(publication_app, name="publication")

ROOT = Path(__file__).resolve().parents[2]
SOURCE_CONFIG = ROOT / "config" / "sources.yaml"
TAXONOMY_CONFIG = ROOT / "config" / "taxonomy" / "ASI-TAXONOMY-1.1.yaml"


@sources_app.command("list")
def sources_list() -> None:
    registry = SourceRegistry.from_yaml(SOURCE_CONFIG)
    for source in registry.sources:
        typer.echo(
            f"{source.id}\t{source.status.value}\t{source.kind.value}\t{','.join(source.domains)}"
        )


@sources_app.command("validate")
def sources_validate() -> None:
    registry = SourceRegistry.from_yaml(SOURCE_CONFIG)
    for source in registry.sources:
        if source.base_url and source.kind.value == "HTTP" and source.role.value == "INPUT":
            registry.validate_url(source.id, str(source.base_url))
    typer.echo(f"Valid: {len(registry.sources)} governed sources")


@taxonomy_app.callback(invoke_without_command=True)
def taxonomy_list(
    ctx: typer.Context,
    vocabulary: Annotated[str | None, typer.Option("--vocabulary", "-v")] = None,
) -> None:
    if ctx.invoked_subcommand:
        return
    taxonomy = load_taxonomy(TAXONOMY_CONFIG)
    typer.echo(taxonomy.id)
    selected = (
        {vocabulary: taxonomy.vocabularies[vocabulary]} if vocabulary else taxonomy.vocabularies
    )
    for name, terms in selected.items():
        typer.echo(f"[{name}]")
        for term in terms:
            typer.echo(f"  {term.key}: {term.label}")


@assertions_app.callback(invoke_without_command=True)
def assertions_list(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand:
        return
    for assertion in gate_a_packet().assertions:
        typer.echo(f"{assertion.id}\t{assertion.state.value}\t{assertion.assertion_key}")


@systems_app.callback(invoke_without_command=True)
def systems_list(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand:
        return
    packet = gate_a_packet()
    vendor_names = {vendor.id: vendor.name for vendor in packet.vendors}
    for system in packet.systems:
        typer.echo(f"{system.id}\t{vendor_names[system.vendor_id]}\t{system.name}")


@app.command("lifecycle")
def lifecycle(system: str) -> None:
    events = [event for event in gate_a_packet().lifecycle_events if event.entity_id == system]
    if not events:
        raise typer.BadParameter(f"no fixture lifecycle history for {system}")
    for event in events:
        typer.echo(f"{event.effective_at}\t{event.state.value}\t{event.evidence_id}")


@app.command("validate-fixtures")
def validate_fixtures() -> None:
    packet = gate_a_packet()
    snapshots = {snapshot.id: snapshot for snapshot in packet.snapshots}
    for evidence in packet.evidence:
        validate_evidence_anchor(evidence, snapshots[evidence.anchor.snapshot_id])
        validate_evidence_classification(evidence)
    typer.echo(
        f"Valid: {len(packet.assertions)} assertions, {len(packet.evidence)} evidence records, "
        f"{len(packet.snapshots)} snapshots"
    )


@app.command("gate-a")
def gate_a(
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    packet = gate_a_packet()
    if dry_run:
        typer.echo(f"Would write Gate A fixture packet with {len(packet.assertions)} assertions")
        return
    payload = packet.model_dump(mode="json")
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        typer.echo(str(output))
    else:
        typer.echo(json.dumps(payload, indent=2))


@app.command("derive")
def derive() -> None:
    packet = gate_a_packet()
    autonomy = derive_autonomy_label(packet.autonomy_assessments[0])
    independent = next(item for item in packet.evidence if item.id == "EV-INDEPENDENT-GRANT")
    panel = derive_capability_evidence_panel(
        "alert-triage",
        [item for item in packet.evidence if item.id == "EV-TRIAGE"],
    )
    assert independent.independence_facets is not None
    typer.echo(f"autonomy={autonomy}")
    typer.echo(f"independence={derive_independence(independent.independence_facets).value}")
    typer.echo(panel.model_dump_json(indent=2))


@app.command("init-db")
def init_db(
    path: Annotated[Path, typer.Option("--path")] = Path("data/asi.db"),
    with_demo: Annotated[bool, typer.Option("--with-demo")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    if dry_run:
        suffix = " and load fixture records" if with_demo else ""
        typer.echo(f"Would initialize SQLite schema at {path}{suffix}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    initialize_authoritative_ledger(path)
    if with_demo:
        database = Database(path)
        with database.transaction() as connection:
            GateAPacketRepository(connection).load(gate_a_packet())
    typer.echo(f"Initialized {path}")


@app.command("collect")
def collect(
    dry_run: Annotated[bool, typer.Option("--dry-run/--no-dry-run")] = True,
) -> None:
    """Collection remains dry-run in fixture mode."""
    if not dry_run:
        raise typer.BadParameter("live collection is disabled in fixture mode")
    registry = SourceRegistry.from_yaml(SOURCE_CONFIG)
    typer.echo(f"Dry run: would inspect {len(registry.sources)} approved sources; fetched 0")


@app.command("changes")
def changes(
    dry_run: Annotated[bool, typer.Option("--dry-run/--no-dry-run")] = True,
) -> None:
    fixture = gate_b_fixture()
    material = sum(item.material_candidate for item in fixture["diffs"])
    prefix = "Dry run: " if dry_run else ""
    typer.echo(f"{prefix}{len(fixture['diffs'])} diffs; {material} material candidates")


@app.command("review")
def review(
    dry_run: Annotated[bool, typer.Option("--dry-run/--no-dry-run")] = True,
) -> None:
    fixture = gate_b_fixture()
    typer.echo(f"{'Dry run: ' if dry_run else ''}{len(fixture['reviews'])} review items pending")


@app.command("contradictions")
def contradictions(
    dry_run: Annotated[bool, typer.Option("--dry-run/--no-dry-run")] = True,
) -> None:
    fixture = gate_b_fixture()
    typer.echo(f"{'Dry run: ' if dry_run else ''}{len(fixture['conflicts'])} conflicts flagged")


@app.command("trends")
def trends() -> None:
    packet = gate_a_packet()
    payload = {
        "preview_to_ga_days": preview_to_ga_velocity(packet.lifecycle_events),
        "new_agents_by_month": new_agents_by_month(packet.agents),
        "decision_impacts": decision_impact_frequency(packet.material_changes),
    }
    typer.echo(json.dumps(payload, indent=2))


@app.command("daily")
def daily(
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run/--no-dry-run")] = True,
) -> None:
    brief = build_daily_brief(gate_a_packet().material_changes[0].confirmed_at.date(), ())  # type: ignore[union-attr]
    if dry_run:
        typer.echo("Dry run: would generate a no-material-change daily brief")
    elif output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(brief.markdown, encoding="utf-8")
        typer.echo(str(output))
    else:
        typer.echo(brief.markdown)


@app.command("weekly-pack")
def weekly_pack(
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run/--no-dry-run")] = True,
) -> None:
    packet = gate_a_packet()
    fixture = gate_b_fixture()
    freshness = {
        item.id: derive_freshness(item.last_verified_at, as_of=NOW) for item in packet.assertions
    }
    pack = build_weekly_pack(
        NOW.date(),
        packet.material_changes,
        fixture["conflicts"],
        freshness,
        {"preview_to_ga_days": preview_to_ga_velocity(packet.lifecycle_events)},
    )
    if dry_run:
        typer.echo("Dry run: would generate weekly ledger-derived evidence pack")
    elif output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(pack.markdown, encoding="utf-8")
        typer.echo(str(output))
    else:
        typer.echo(pack.markdown)


@pipeline_app.command("daily")
def pipeline_daily(
    output_root: Annotated[Path, typer.Option("--output-root")] = Path("generated"),
    database: Annotated[Path | None, typer.Option("--database")] = None,
    demo: Annotated[bool, typer.Option("--demo")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run/--no-dry-run")] = True,
) -> None:
    try:
        artifact = run_daily_pipeline(
            output_root,
            dry_run=dry_run,
            database_path=database,
            demo=demo,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    prefix = "Dry run: " if dry_run else ""
    typer.echo(
        f"{prefix}prepared {artifact.branch} with {len(artifact.files)} file(s); "
        "human merge required"
    )


@pipeline_app.command("weekly")
def pipeline_weekly(
    output_root: Annotated[Path, typer.Option("--output-root")] = Path("generated"),
    database: Annotated[Path | None, typer.Option("--database")] = None,
    demo: Annotated[bool, typer.Option("--demo")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run/--no-dry-run")] = True,
) -> None:
    try:
        artifact = run_weekly_pipeline(
            output_root,
            dry_run=dry_run,
            database_path=database,
            demo=demo,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    prefix = "Dry run: " if dry_run else ""
    typer.echo(
        f"{prefix}prepared {artifact.branch} with {len(artifact.files)} file(s); "
        "human merge required"
    )


@app.command("export-site")
def export_site(
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("site/src/data/ledger.json"),
    database: Annotated[Path | None, typer.Option("--database")] = None,
    demo: Annotated[bool, typer.Option("--demo")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run/--no-dry-run")] = True,
) -> None:
    try:
        data = write_site_data(
            output,
            dry_run=dry_run,
            database_path=database,
            demo=demo,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    prefix = "Dry run: would write" if dry_run else "Wrote"
    typer.echo(f"{prefix} {len(data['systems'])} systems to {output}")


@publication_app.command("export")
def publication_export(
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    database: Annotated[Path | None, typer.Option("--database")] = None,
) -> None:
    config = load_runtime_config()
    if database is not None:
        config = config.model_copy(update={"database_path": database.resolve()})
    try:
        manifest = PublicationProjectionService(config).export(output_root=output)
    except (FileNotFoundError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(
        f"Wrote {manifest.content_count} public records with {len(manifest.files)} verified file(s)"
    )


@publication_app.command("validate")
def publication_validate(
    bundle: Annotated[Path, typer.Option("--bundle")] = Path("publication"),
) -> None:
    try:
        manifest = validate_publication_bundle(bundle)
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"Valid public bundle: {len(manifest.files)} file(s)")


@publication_app.command("publish")
def publication_publish(
    bundle: Annotated[Path, typer.Option("--bundle")] = Path("publication"),
) -> None:
    try:
        result = GitHubDraftPublisher(load_runtime_config()).publish(bundle)
    except PublicationError as exc:
        raise typer.BadParameter(f"{exc.category.value}: {exc.safe_message}") from exc
    typer.echo(
        f"Draft PR #{result.pull_request_number} on {result.branch}; "
        f"duplicate={str(result.duplicate).lower()}"
    )


if __name__ == "__main__":
    app()
