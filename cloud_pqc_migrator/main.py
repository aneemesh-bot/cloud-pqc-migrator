from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.table import Table

from cloud_pqc_migrator.models import CBoM, CloudProvider
from cloud_pqc_migrator.remediation.llm_backends import DEFAULT_ANTHROPIC_MODEL, PROVIDERS
from cloud_pqc_migrator.ui.console import console


def _llm_options(f):
    """Shared --llm-provider / --model / --ollama-host options."""
    f = click.option(
        "--ollama-host",
        default=None,
        metavar="URL",
        help="Ollama server URL (default: $OLLAMA_HOST or http://localhost:11434).",
    )(f)
    f = click.option(
        "--model",
        default=None,
        envvar="PQC_LLM_MODEL",
        metavar="NAME",
        help=(
            "Model to use for remediation: any Anthropic model ID or Ollama model tag. "
            f"Anthropic default: {DEFAULT_ANTHROPIC_MODEL}. Required for Ollama."
        ),
    )(f)
    f = click.option(
        "--llm-provider",
        type=click.Choice(PROVIDERS),
        default="anthropic",
        show_default=True,
        envvar="PQC_LLM_PROVIDER",
        help="LLM backend used to generate remediations.",
    )(f)
    return f


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
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default="WARNING",
    show_default=True,
    help="Logging level for the audit trail.",
)
@click.option(
    "--log-file",
    type=click.Path(),
    default=None,
    metavar="PATH",
    help="Write audit log to this file (default: disabled).",
)
@_llm_options
def scan(
    provider: str,
    dry_run: bool,
    output_cbom: str | None,
    skip_execution: bool,
    t_cover_months: int,
    t_proj_months: int,
    max_remediations: int | None,
    log_level: str,
    log_file: str | None,
    llm_provider: str,
    model: str | None,
    ollama_host: str | None,
) -> None:
    """Full scan: authenticate → discover → triage → remediate → approve → execute."""
    from cloud_pqc_migrator.logger import configure_logging, log
    configure_logging(level=log_level, log_file=Path(log_file) if log_file else None)

    from cloud_pqc_migrator.auth import AWSCredentialProvider, GCPCredentialProvider
    from cloud_pqc_migrator.discovery import run_aws_discovery, run_gcp_discovery
    from cloud_pqc_migrator.triage import evaluate
    from cloud_pqc_migrator.remediation import generate_all_remediations
    from cloud_pqc_migrator.execution import run_approval_gate
    from cloud_pqc_migrator.ui.progress import discovery_progress, remediation_progress

    cloud_provider = CloudProvider(provider)
    log.info("scan_start provider=%s dry_run=%s", provider, dry_run)

    # ── LLM backend pre-flight check ────────────────────────────────────────
    backend = None
    if not skip_execution:
        from cloud_pqc_migrator.remediation import LLMBackendError, get_backend
        try:
            backend = get_backend(llm_provider, model, ollama_host)
            backend.preflight()
        except LLMBackendError as exc:
            if dry_run:
                console.print(
                    f"[bold yellow]Warning:[/] {exc}\n"
                    "Remediation generation (Step 4) will be skipped.\n"
                    "Fix the LLM backend configuration and re-run to generate remediation proposals."
                )
                skip_execution = True
            else:
                console.print(
                    f"[bold red]Error:[/] {exc}\n\n"
                    "To run discovery and triage without the LLM step, add --skip-execution.\n"
                    "To test with mock cloud data, add --dry-run --skip-execution."
                )
                sys.exit(1)
        else:
            log.info("llm_backend provider=%s model=%s", backend.name, backend.model)

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

    log.info("discovery_complete assets=%d commands=%d", len(cbom.assets), len(cbom.cli_commands_executed))
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
    log.info("triage_complete gaps=%d", len(gaps))

    _print_gap_summary(gaps)

    if not gaps:
        console.print("[bold green]No cryptographic gaps detected. Environment is PQC-compliant![/]")
        return

    if skip_execution:
        console.print("[bold yellow]--skip-execution set. Stopping before remediation generation.[/]")
        return

    # ── Step 4: Remediation Generation ─────────────────────────────────────
    assert backend is not None
    console.rule(f"[bold blue]Step 4 — Remediation Generation ({backend.name}: {backend.model})[/]")
    gaps_to_remediate = gaps[:max_remediations] if max_remediations else gaps

    if len(gaps_to_remediate) < len(gaps):
        log.warning(
            "remediation_cap applied=%d deferred=%d",
            len(gaps_to_remediate),
            len(gaps) - len(gaps_to_remediate),
        )
        console.print(
            f"[yellow]Capping at {max_remediations} remediations "
            f"({len(gaps) - len(gaps_to_remediate)} gaps deferred).[/]"
        )

    remediations: list = []
    with remediation_progress(len(gaps_to_remediate), label=backend.name) as (progress, task):
        def on_remediation(done: int, total: int) -> None:
            progress.update(task, completed=done)

        remediations = generate_all_remediations(
            gaps_to_remediate, progress_callback=on_remediation, backend=backend
        )

    # ── Step 5: Approval Gate ───────────────────────────────────────────────
    console.rule("[bold blue]Step 5 — Human-in-the-Loop Approval Gate[/]")
    run_approval_gate(remediations, creds, dry_run=dry_run)
    log.info("scan_complete")


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
@_llm_options
def remediate_only(
    cbom_file: str,
    max_remediations: int | None,
    llm_provider: str,
    model: str | None,
    ollama_host: str | None,
) -> None:
    """Generate remediations from an existing CBoM without executing them."""
    from cloud_pqc_migrator.triage import evaluate
    from cloud_pqc_migrator.remediation import LLMBackendError, generate_all_remediations, get_backend
    from cloud_pqc_migrator.ui.progress import remediation_progress

    try:
        backend = get_backend(llm_provider, model, ollama_host)
        backend.preflight()
    except LLMBackendError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        sys.exit(1)

    cbom_path = Path(cbom_file)
    cbom = CBoM.model_validate_json(cbom_path.read_text())
    gaps = evaluate(cbom)
    _print_gap_summary(gaps)

    if not gaps:
        console.print("[bold green]No gaps to remediate.[/]")
        return

    gaps_to_remediate = gaps[:max_remediations] if max_remediations else gaps
    remediations = []
    console.print(f"Using [bold]{backend.name}[/] model [bold]{backend.model}[/]")
    with remediation_progress(len(gaps_to_remediate), label=backend.name) as (progress, task):
        def on_r(done: int, total: int) -> None:
            progress.update(task, completed=done)
        remediations = generate_all_remediations(
            gaps_to_remediate, progress_callback=on_r, backend=backend
        )

    console.rule("[bold]Generated Remediations[/]")
    for i, r in enumerate(remediations, 1):
        from cloud_pqc_migrator.ui.panels import display_approval_panel
        display_approval_panel(r, index=i, total=len(remediations), dry_run=True)


@cli.command("models")
@click.option(
    "--llm-provider",
    type=click.Choice(PROVIDERS),
    default="anthropic",
    show_default=True,
    envvar="PQC_LLM_PROVIDER",
    help="LLM backend whose models to list.",
)
@click.option(
    "--ollama-host",
    default=None,
    metavar="URL",
    help="Ollama server URL (default: $OLLAMA_HOST or http://localhost:11434).",
)
def models(llm_provider: str, ollama_host: str | None) -> None:
    """List the models available for --model on the chosen LLM backend."""
    from cloud_pqc_migrator.remediation import AnthropicBackend, LLMBackendError, OllamaBackend

    backend = (
        AnthropicBackend() if llm_provider == "anthropic"
        else OllamaBackend(model="", host=ollama_host)
    )
    try:
        names = backend.list_models()
    except LLMBackendError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        sys.exit(1)

    table = Table(title=f"Available {llm_provider} models")
    table.add_column("Model")
    table.add_column("Default", justify="center")
    for name in names:
        is_default = llm_provider == "anthropic" and name == DEFAULT_ANTHROPIC_MODEL
        table.add_row(name, "[green]✓[/]" if is_default else "")
    console.print(table)
    if not names:
        hint = "ollama pull <model>" if llm_provider == "ollama" else "check your API key"
        console.print(f"[yellow]No models found ({hint}).[/]")


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
