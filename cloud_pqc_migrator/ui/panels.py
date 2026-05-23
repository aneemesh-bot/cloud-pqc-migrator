from __future__ import annotations

from rich.columns import Columns
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cloud_pqc_migrator.models import Priority, Remediation
from .console import console

_PRIORITY_COLORS = {
    Priority.CRITICAL: "bold red",
    Priority.HIGH: "bold yellow",
    Priority.MEDIUM: "bold cyan",
}

_PRIORITY_LABELS = {
    Priority.CRITICAL: "CRITICAL",
    Priority.HIGH: "HIGH",
    Priority.MEDIUM: "MEDIUM",
}


def display_approval_panel(
    remediation: Remediation,
    index: int,
    total: int,
    dry_run: bool = False,
) -> None:
    gap = remediation.gap
    asset = gap.asset
    priority = gap.priority
    color = _PRIORITY_COLORS.get(priority, "white")
    priority_label = _PRIORITY_LABELS.get(priority, str(priority.value))

    dry_tag = "  [bold yellow]\\[DRY RUN][/]" if dry_run else ""
    title = (
        f"REMEDIATION PROPOSAL [{index}/{total}] — "
        f"Priority {priority.value}: [{color}]{priority_label}[/]{dry_tag}"
    )

    table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    table.add_column("Field", style="bold", min_width=22)
    table.add_column("Value", overflow="fold")

    table.add_row("Resource ID", asset.resource_id)
    table.add_row("Resource Kind", asset.resource_kind.value)
    table.add_row("Provider", asset.provider.value.upper())
    table.add_row("Region / Location", asset.region or asset.project or "global")
    table.add_row("Internet-Facing", "Yes" if asset.is_internet_facing else "No")
    table.add_section()

    table.add_row("Cryptographic Gap", gap.description)
    table.add_row("FIPS Violations", ", ".join(gap.fips_references))
    if gap.t_start:
        table.add_row(
            "Migration Deadline",
            f"[bold red]Start by {gap.t_start.strftime('%Y-%m-%d')}[/]",
        )
    table.add_section()

    table.add_row("Current State", gap.current_state)
    table.add_row("Target State", f"[green]{gap.target_state}[/]")
    table.add_section()

    table.add_row(
        "Remediation Command",
        f"[bold white on dark_green]{remediation.cli_command}[/]",
    )
    table.add_row(
        "Rollback Command",
        f"[dim]{remediation.rollback_command}[/]",
    )

    if remediation.llm_reasoning:
        table.add_section()
        table.add_row("Claude Reasoning", f"[dim italic]{remediation.llm_reasoning}[/]")

    panel = Panel(
        table,
        title=title,
        border_style=color,
        padding=(1, 2),
    )
    console.print(panel)


def display_summary_table(remediations: list[Remediation]) -> None:
    from cloud_pqc_migrator.models import RemediationStatus

    table = Table(title="Remediation Summary", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Resource", overflow="fold")
    table.add_column("Priority", width=10)
    table.add_column("Status", width=14)

    status_colors = {
        RemediationStatus.EXECUTED: "bold green",
        RemediationStatus.ROLLED_BACK: "bold yellow",
        RemediationStatus.REJECTED: "dim",
        RemediationStatus.FAILED: "bold red",
        RemediationStatus.PENDING: "dim",
        RemediationStatus.APPROVED: "bold blue",
    }

    for i, r in enumerate(remediations, 1):
        color = status_colors.get(r.status, "white")
        priority_color = _PRIORITY_COLORS.get(r.gap.priority, "white")
        table.add_row(
            str(i),
            r.gap.asset.resource_id[-60:],
            f"[{priority_color}]{_PRIORITY_LABELS[r.gap.priority]}[/]",
            f"[{color}]{r.status.value.upper()}[/]",
        )

    console.print(table)
