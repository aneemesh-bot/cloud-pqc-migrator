from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click
from rich.table import Table

from cloud_pqc_migrator.models import CBoM, CloudProvider
from cloud_pqc_migrator.ui.console import console


@click.group()
@click.version_option("0.1.0", prog_name="cloud-pqc-migrator")
def cli() -> None:
    """Post-Quantum Cryptography Migration Engine for AWS and GCP.

    Audits cloud infrastructure for cryptographic gaps against FIPS 203/204/205
    and CNSA 2.0 standards, then generates and executes remediations with
    human-in-the-loop approval.
    """


@cli.command()
@click.option(
    "--provider",
    type=click.Choice(["aws", "gcp"]),
    required=True,
    help="Cloud provider to scan.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Use mock data for discovery; display but do not execute remediations.",
)
@click.option(
    "--output-cbom",
    type=click.Path(),
    default=None,
    metavar="PATH",
    help="Write the discovered CBoM JSON to a file after discovery.",
)
@click.option(
    "--skip-execution",
    is_flag=True,
    default=False,
    help="Run discovery and triage but stop before remediation generation.",
)
@click.option(
    "--t-cover-months",
    default=24,
    type=int,
    show_default=True,
    help="Data sensitivity window in months for T_start calculation.",
)
@click.option(
    "--t-proj-months",
    default=6,
    type=int,
    show_default=True,
    help="Estimated project duration in months for T_start calculation.",
)
@click.option(
    "--max-remediations",
    default=None,
    type=int,
    metavar="N",
    help="Cap the number of gaps sent to the LLM (useful for large environments).",
)
def scan(
    provider: str,
    dry_run: bool,
    output_cbom: str | None,
    skip_execution: bool,
    t_cover_months: int,
    t_proj_months: int,
    max_remediations: int | None,
) -> None:
    """Full scan: authenticate → discover → triage → remediate → approve → execute."""
    from cloud_pqc_migrator.auth import AWSCredentialProvider, GCPCredentialProvider
    from cloud_pqc_migrator.discovery import run_aws_discovery, run_gcp_discovery
    from cloud_pqc_migrator.triage import evaluate
    from cloud_pqc_migrator.remediation import generate_all_remediations
    from cloud_pqc_migrator.execution import run_approval_gate
    from cloud_pqc_migrator.ui.progress import discovery_progress, remediation_progress

    cloud_provider = CloudProvider(provider)

    # ── API key pre-flight check ────────────────────────────────────────────
    has_api_key = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    if not has_api_key:
        if dry_run:
            console.print(
                "[bold yellow]Warning:[/] ANTHROPIC_API_KEY is not set. "
                "Remediation generation (Step 4) will be skipped.\n"
                "Set the variable and re-run to generate AI remediation proposals."
            )
            skip_execution = True
        else:
            console.print(
                "[bold red]Error:[/] ANTHROPIC_API_KEY is not set.\n"
                "The remediation engine requires an Anthropic API key.\n\n"
                "  export ANTHROPIC_API_KEY=sk-ant-...\n\n"
                "To run discovery and triage without the LLM step, add --skip-execution.\n"
                "To test with mock cloud data, add --dry-run --skip-execution."
            )
            sys.exit(1)

    # ── Step 1: Authentication ──────────────────────────────────────────────
    console.rule(f"[bold blue]Step 1 — {provider.upper()} Authentication[/]")
    if dry_run:
        console.print("[bold yellow][DRY RUN] Skipping live authentication — using mock credentials.[/]")
        from cloud_pqc_migrator.auth.base import CredentialBundle
        creds = CredentialBundle(provider=cloud_provider, masked_display="[DRY RUN mock]")
    else:
        auth_provider = (
            AWSCredentialProvider() if cloud_provider == CloudProvider.AWS
            else GCPCredentialProvider()
        )
        creds = auth_provider.prompt_and_load()
        console.print(f"Credentials loaded: {creds.masked_display}")
        if not auth_provider.validate(creds):
            console.print("[bold red]Credential validation failed. Aborting.[/]")
            sys.exit(1)

    # ── Step 2: Discovery ───────────────────────────────────────────────────
    console.rule("[bold blue]Step 2 — Cloud Discovery & CBoM Extraction[/]")
    discover_fn = run_aws_discovery if cloud_provider == CloudProvider.AWS else run_gcp_discovery

    steps_done: list[str] = []

    with discovery_progress() as progress:
        task = progress.add_task("Scanning cloud infrastructure...", total=None)

        def on_step(desc: str) -> None:
            progress.update(task, description=desc)
            steps_done.append(desc)

        cbom = discover_fn(creds, dry_run=dry_run, progress_callback=on_step)

    console.print(
        f"[green]Discovery complete.[/] Found [bold]{len(cbom.assets)}[/] cryptographic assets "
        f"across [bold]{len(cbom.cli_commands_executed)}[/] CLI commands."
    )

    if output_cbom:
        cbom_path = Path(output_cbom)
        cbom_path.write_text(cbom.model_dump_json(indent=2))
        console.print(f"CBoM written to [bold]{cbom_path}[/]")

    # ── Step 3: Triage ──────────────────────────────────────────────────────
    console.rule("[bold blue]Step 3 — PQC Compliance Triage[/]")
    gaps = evaluate(cbom, t_proj_months=t_proj_months)

    _print_gap_summary(gaps)

    if not gaps:
        console.print("[bold green]No cryptographic gaps detected. Environment is PQC-compliant![/]")
        return

    if skip_execution:
        console.print("[bold yellow]--skip-execution set. Stopping before remediation generation.[/]")
        return

    # ── Step 4: Remediation Generation ─────────────────────────────────────
    console.rule("[bold blue]Step 4 — Remediation Generation (Claude AI)[/]")
    gaps_to_remediate = gaps[:max_remediations] if max_remediations else gaps

    if len(gaps_to_remediate) < len(gaps):
        console.print(
            f"[yellow]Capping at {max_remediations} remediations "
            f"({len(gaps) - len(gaps_to_remediate)} gaps deferred).[/]"
        )

    remediations: list = []
    with remediation_progress(len(gaps_to_remediate)) as (progress, task):
        def on_remediation(done: int, total: int) -> None:
            progress.update(task, completed=done)

        remediations = generate_all_remediations(gaps_to_remediate, progress_callback=on_remediation)

    # ── Step 5: Approval Gate ───────────────────────────────────────────────
    console.rule("[bold blue]Step 5 — Human-in-the-Loop Approval Gate[/]")
    run_approval_gate(remediations, creds, dry_run=dry_run)


@cli.command("triage-only")
@click.argument("cbom_file", type=click.Path(exists=True))
@click.option("--t-proj-months", default=6, type=int, show_default=True)
def triage_only(cbom_file: str, t_proj_months: int) -> None:
    """Run triage against an existing CBoM JSON file (no cloud auth needed)."""
    from cloud_pqc_migrator.triage import evaluate

    cbom_path = Path(cbom_file)
    cbom = CBoM.model_validate_json(cbom_path.read_text())
    console.print(f"Loaded CBoM with [bold]{len(cbom.assets)}[/] assets from {cbom_path}")

    gaps = evaluate(cbom, t_proj_months=t_proj_months)
    _print_gap_summary(gaps)

    if not gaps:
        console.print("[bold green]No cryptographic gaps detected.[/]")


@cli.command("remediate-only")
@click.argument("cbom_file", type=click.Path(exists=True))
@click.option(
    "--max-remediations",
    default=None,
    type=int,
    metavar="N",
    help="Cap the number of gaps sent to the LLM.",
)
def remediate_only(cbom_file: str, max_remediations: int | None) -> None:
    """Generate remediations from an existing CBoM without executing them."""
    from cloud_pqc_migrator.triage import evaluate
    from cloud_pqc_migrator.remediation import generate_all_remediations
    from cloud_pqc_migrator.ui.progress import remediation_progress

    cbom_path = Path(cbom_file)
    cbom = CBoM.model_validate_json(cbom_path.read_text())
    gaps = evaluate(cbom)
    _print_gap_summary(gaps)

    if not gaps:
        console.print("[bold green]No gaps to remediate.[/]")
        return

    gaps_to_remediate = gaps[:max_remediations] if max_remediations else gaps
    remediations = []
    with remediation_progress(len(gaps_to_remediate)) as (progress, task):
        def on_r(done: int, total: int) -> None:
            progress.update(task, completed=done)
        remediations = generate_all_remediations(gaps_to_remediate, progress_callback=on_r)

    console.rule("[bold]Generated Remediations[/]")
    for i, r in enumerate(remediations, 1):
        from cloud_pqc_migrator.ui.panels import display_approval_panel
        display_approval_panel(r, index=i, total=len(remediations), dry_run=True)


def _print_gap_summary(gaps: list) -> None:
    from cloud_pqc_migrator.models import Priority

    if not gaps:
        return

    counts = {p: 0 for p in Priority}
    for g in gaps:
        counts[g.priority] += 1

    table = Table(title=f"PQC Gap Assessment — {len(gaps)} gap(s) found", show_lines=True)
    table.add_column("Priority", style="bold")
    table.add_column("Label")
    table.add_column("Count", justify="right")
    table.add_column("Description")

    rows = [
        (Priority.CRITICAL, "bold red", "Cannot negotiate TLS 1.3; zero crypto-agility"),
        (Priority.HIGH, "bold yellow", "Internet-facing; Harvest-Now-Decrypt-Later risk"),
        (Priority.MEDIUM, "bold cyan", "IAM, signing, internal PKI, VPN infrastructure"),
    ]
    for priority, color, desc in rows:
        if counts[priority]:
            table.add_row(
                f"[{color}]{priority.value}[/]",
                f"[{color}]{priority.name}[/]",
                str(counts[priority]),
                desc,
            )

    console.print(table)


if __name__ == "__main__":
    cli()
