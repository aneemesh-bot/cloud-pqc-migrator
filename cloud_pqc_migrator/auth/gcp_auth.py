from __future__ import annotations

import getpass
import json
import os
import platform
import sys
import tempfile

import click

from cloud_pqc_migrator.models import CloudProvider
from .base import CredentialBundle, CredentialProvider, run_subprocess


class GCPCredentialProvider(CredentialProvider):
    def __init__(self) -> None:
        self._tmp_file: tempfile.NamedTemporaryFile | None = None  # type: ignore[type-arg]

    def prompt_and_load(self) -> CredentialBundle:
        click.echo("\n[GCP Authentication]")
        click.echo("Choose credential mode:")
        click.echo("  1) OAuth 2.0 access token")
        click.echo("  2) Service account JSON key")
        mode = click.prompt("Mode", type=click.Choice(["1", "2"]), default="1")

        if mode == "1":
            return self._oauth_token()
        return self._service_account_json()

    def _oauth_token(self) -> CredentialBundle:
        click.echo("Paste your OAuth 2.0 access token (hidden):")
        token = getpass.getpass("Access token: ")
        env_vars = {
            "CLOUDSDK_AUTH_ACCESS_TOKEN": token,
            "CLOUDSDK_CORE_FORMAT": "json",
        }
        return CredentialBundle(
            provider=CloudProvider.GCP,
            env_vars=env_vars,
            masked_display="GCP OAuth token (****)",
        )

    def _service_account_json(self) -> CredentialBundle:
        click.echo("Paste your service account JSON key content, then press Enter twice:")
        lines: list[str] = []
        blank_count = 0
        while blank_count < 1:
            line = sys.stdin.readline().rstrip("\n")
            if line == "" and lines:
                blank_count += 1
            else:
                blank_count = 0
                lines.append(line)
        json_content = "\n".join(lines)

        try:
            sa_data = json.loads(json_content)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid service account JSON: {exc}") from exc

        client_email = sa_data.get("client_email", "unknown")

        # Write to a temporary file; on Linux we use /proc/self/fd for in-memory semantics
        self._tmp_file = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        )
        self._tmp_file.write(json_content)
        self._tmp_file.flush()
        self._tmp_file.close()

        env_vars = {
            "GOOGLE_APPLICATION_CREDENTIALS": self._tmp_file.name,
            "CLOUDSDK_CORE_FORMAT": "json",
        }
        return CredentialBundle(
            provider=CloudProvider.GCP,
            env_vars=env_vars,
            masked_display=f"GCP Service Account: {client_email}",
        )

    def validate(self, bundle: CredentialBundle) -> bool:
        rc, stdout, stderr = run_subprocess(
            ["gcloud", "auth", "print-access-token"],
            bundle.build_env(),
        )
        if rc == 0:
            click.echo("  GCP token validated successfully.")
            return True
        click.echo(f"  GCP validation failed: {stderr.strip()}", err=True)
        return False

    def clear(self, bundle: CredentialBundle) -> None:
        super().clear(bundle)
        if self._tmp_file and os.path.exists(self._tmp_file.name):
            try:
                with open(self._tmp_file.name, "w") as f:
                    f.write("")
                os.unlink(self._tmp_file.name)
            except OSError:
                pass
            self._tmp_file = None
