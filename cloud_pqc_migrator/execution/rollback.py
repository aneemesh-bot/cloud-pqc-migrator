from __future__ import annotations

import shlex
import subprocess

from cloud_pqc_migrator.auth.base import CredentialBundle
from cloud_pqc_migrator.ui.console import console


def execute_rollback(rollback_command: str, creds: CredentialBundle) -> bool:
    """
    Execute the pre-loaded rollback command.
    The command string is held in a local variable — never written to disk.
    Returns True if rollback succeeded.
    """
    console.print(f"\n[bold yellow]Executing rollback:[/] {rollback_command}")
    try:
        cmd = shlex.split(rollback_command)
    except ValueError as exc:
        console.print(f"[bold red]Rollback command parse error:[/] {exc}")
        return False

    env = creds.build_env()
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if result.returncode == 0:
        console.print("[bold green]Rollback succeeded.[/]")
        return True
    console.print(f"[bold red]Rollback failed (rc={result.returncode}):[/] {result.stderr.strip()}")
    return False
