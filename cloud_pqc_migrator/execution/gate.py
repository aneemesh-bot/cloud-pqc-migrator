from __future__ import annotations

import shlex
import subprocess

import click

from cloud_pqc_migrator.auth.base import CredentialBundle
from cloud_pqc_migrator.models import Remediation, RemediationStatus
from cloud_pqc_migrator.ui.console import console
from cloud_pqc_migrator.ui.panels import display_approval_panel, display_summary_table
from .health_check import run_health_check
from .rollback import execute_rollback


def _execute_command(cmd_str: str, creds: CredentialBundle) -> tuple[bool, str]:
    try:
        cmd = shlex.split(cmd_str)
    except ValueError as exc:
        return False, str(exc)
    env = creds.build_env()
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    output = result.stdout + result.stderr
    return result.returncode == 0, output


def _prompt_choice() -> str:
    console.print(
        "\n  [bold green]\\[A][/] Approve and Execute    "
        "[bold yellow]\\[S][/] Skip    "
        "[bold red]\\[Q][/] Quit session\n"
    )
    while True:
        choice = click.prompt("Choice", prompt_suffix=" > ").strip().lower()
        if choice in ("a", "approve"):
            return "approve"
        if choice in ("s", "skip"):
            return "skip"
        if choice in ("q", "quit"):
            return "quit"
        console.print("[dim]Please enter A, S, or Q.[/]")


def run_approval_gate(
    remediations: list[Remediation],
    creds: CredentialBundle,
    dry_run: bool = False,
) -> list[Remediation]:
    total = len(remediations)
    console.rule("[bold]Human-in-the-Loop Approval Gate[/]")

    for i, remediation in enumerate(remediations, 1):
        display_approval_panel(remediation, index=i, total=total, dry_run=dry_run)

        choice = _prompt_choice()

        if choice == "quit":
            console.print("[bold red]Session aborted by user.[/]")
            break

        if choice == "skip":
            remediation.status = RemediationStatus.REJECTED
            console.print("[dim]Skipped.[/]\n")
            continue

        # Approved
        remediation.status = RemediationStatus.APPROVED
        rollback_cmd = remediation.rollback_command  # loaded into local var before execution

        if dry_run:
            console.print(
                f"[bold yellow][DRY RUN][/] Would execute:\n  [bold white]{remediation.cli_command}[/]"
            )
            remediation.status = RemediationStatus.EXECUTED
            console.print("[dim]Status: EXECUTED (dry-run)[/]\n")
            continue

        console.print(f"\n[bold]Executing:[/] {remediation.cli_command}")
        success, output = _execute_command(remediation.cli_command, creds)
        remediation.execution_output = output

        if not success:
            console.print(f"[bold red]Execution failed:[/]\n{output}")
            remediation.status = RemediationStatus.FAILED
            console.print()
            continue

        console.print("[green]Execution succeeded.[/]")
        healthy = run_health_check(remediation, creds)
        remediation.health_check_passed = healthy

        if not healthy:
            console.print("[bold red]Health check failed — initiating rollback...[/]")
            execute_rollback(rollback_cmd, creds)
            remediation.status = RemediationStatus.ROLLED_BACK
        else:
            remediation.status = RemediationStatus.EXECUTED
            console.print("[bold green]Health check passed. Change is live.[/]")

        console.print()

    console.rule("[bold]Session Complete[/]")
    display_summary_table(remediations)
    return remediations
