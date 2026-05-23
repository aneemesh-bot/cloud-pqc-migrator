from __future__ import annotations

import json
import subprocess
from typing import Any

from cloud_pqc_migrator.auth.base import CredentialBundle
from .mock_data import MOCK_RESPONSES


class CLICommandError(RuntimeError):
    def __init__(self, cmd: list[str], returncode: int, stderr: str) -> None:
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"Command {' '.join(cmd)!r} failed (rc={returncode}): {stderr.strip()}")


def run_cli_command(
    cmd: list[str],
    creds: CredentialBundle,
    dry_run: bool = False,
    mock_key: str | None = None,
) -> Any:
    if dry_run:
        if mock_key and mock_key in MOCK_RESPONSES:
            return MOCK_RESPONSES[mock_key]
        return {}

    env = creds.build_env()
    env["AWS_DEFAULT_OUTPUT"] = "json"
    env["CLOUDSDK_CORE_FORMAT"] = "json"

    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        raise CLICommandError(cmd, result.returncode, result.stderr)

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.stdout
