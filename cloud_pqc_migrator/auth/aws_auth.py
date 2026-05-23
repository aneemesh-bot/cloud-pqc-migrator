from __future__ import annotations

import getpass
import json
from datetime import datetime, timezone

import click

from cloud_pqc_migrator.models import CloudProvider
from .base import CredentialBundle, CredentialProvider, run_subprocess


class AWSCredentialProvider(CredentialProvider):
    def prompt_and_load(self) -> CredentialBundle:
        click.echo("\n[AWS Authentication]")
        click.echo("Choose credential mode:")
        click.echo("  1) Role ARN + External ID (STS AssumeRole)")
        click.echo("  2) Direct Access/Secret/Session tokens")
        mode = click.prompt("Mode", type=click.Choice(["1", "2"]), default="2")

        if mode == "1":
            return self._assume_role()
        return self._direct_tokens()

    def _assume_role(self) -> CredentialBundle:
        role_arn = click.prompt("Role ARN (e.g. arn:aws:iam::123456789012:role/PQCScanner)")
        external_id = click.prompt("External ID", default="", show_default=False)
        session_name = click.prompt("Session name", default="pqc-migrator-session")

        cmd = [
            "aws", "sts", "assume-role",
            "--role-arn", role_arn,
            "--role-session-name", session_name,
            "--output", "json",
        ]
        if external_id:
            cmd += ["--external-id", external_id]

        import os
        rc, stdout, stderr = run_subprocess(cmd, os.environ.copy())
        if rc != 0:
            raise RuntimeError(f"STS AssumeRole failed: {stderr.strip()}")

        data = json.loads(stdout)
        creds = data["Credentials"]
        expires_at = datetime.fromisoformat(creds["Expiration"].replace("Z", "+00:00"))

        env_vars = {
            "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
            "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
            "AWS_SESSION_TOKEN": creds["SessionToken"],
            "AWS_DEFAULT_OUTPUT": "json",
        }
        return CredentialBundle(
            provider=CloudProvider.AWS,
            env_vars=env_vars,
            masked_display=f"AWS Role: {role_arn} (expires {expires_at.strftime('%H:%M UTC')})",
            expires_at=expires_at,
        )

    def _direct_tokens(self) -> CredentialBundle:
        click.echo("Enter AWS credentials (input is hidden):")
        access_key = getpass.getpass("AWS_ACCESS_KEY_ID: ")
        secret_key = getpass.getpass("AWS_SECRET_ACCESS_KEY: ")
        session_token = getpass.getpass("AWS_SESSION_TOKEN (leave blank if none): ")

        env_vars: dict[str, str] = {
            "AWS_ACCESS_KEY_ID": access_key,
            "AWS_SECRET_ACCESS_KEY": secret_key,
            "AWS_DEFAULT_OUTPUT": "json",
        }
        if session_token:
            env_vars["AWS_SESSION_TOKEN"] = session_token

        account_hint = access_key[:4] + "****" if len(access_key) >= 4 else "****"
        return CredentialBundle(
            provider=CloudProvider.AWS,
            env_vars=env_vars,
            masked_display=f"AWS Direct tokens (key: {account_hint})",
        )

    def validate(self, bundle: CredentialBundle) -> bool:
        rc, stdout, stderr = run_subprocess(
            ["aws", "sts", "get-caller-identity", "--output", "json"],
            bundle.build_env(),
        )
        if rc == 0:
            data = json.loads(stdout)
            click.echo(f"  Authenticated as: {data.get('Arn', 'unknown')}")
            return True
        click.echo(f"  AWS validation failed: {stderr.strip()}", err=True)
        return False

    def refresh_if_needed(self, bundle: CredentialBundle) -> CredentialBundle:
        if bundle.will_expire_soon() and bundle.env_vars.get("AWS_SESSION_TOKEN"):
            click.echo("AWS credentials expiring soon — refreshing...")
            new_bundle = self.prompt_and_load()
            self.clear(bundle)
            return new_bundle
        return bundle
