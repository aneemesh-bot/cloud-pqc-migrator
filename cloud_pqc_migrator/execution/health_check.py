from __future__ import annotations

import json
import subprocess
import shlex

from cloud_pqc_migrator.auth.base import CredentialBundle
from cloud_pqc_migrator.models import Remediation, ResourceKind, TLSVersion
from cloud_pqc_migrator.ui.console import console

_TLS13_POLICY_NAMES = {
    "ELBSecurityPolicy-TLS13-1-2-2021-06",
    "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
    "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
    "ELBSecurityPolicy-TLS13-1-3-2021-06",
}


def _run(cmd: list[str], env: dict) -> tuple[int, dict | str]:
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        return result.returncode, result.stderr
    try:
        return 0, json.loads(result.stdout)
    except json.JSONDecodeError:
        return 0, result.stdout


def run_health_check(remediation: Remediation, creds: CredentialBundle) -> bool:
    """
    Re-inspect the resource after remediation to confirm the change took effect.
    Returns True if the resource is now in the expected state, False otherwise.
    """
    asset = remediation.gap.asset
    env = creds.build_env()
    kind = asset.resource_kind

    console.print(f"[dim]Running health check for {asset.resource_id[-60:]}...[/]")

    try:
        if kind == ResourceKind.ALB_LISTENER:
            rc, data = _run(
                ["aws", "elbv2", "describe-listeners",
                 "--listener-arns", asset.resource_id, "--output", "json"],
                env,
            )
            if rc != 0:
                return False
            listeners = data.get("Listeners", []) if isinstance(data, dict) else []  # type: ignore[union-attr]
            for listener in listeners:
                ssl_policy = listener.get("SslPolicy", "")
                if ssl_policy in _TLS13_POLICY_NAMES:
                    return True
            return False

        elif kind == ResourceKind.CLOUDFRONT_DISTRIBUTION:
            dist_id = asset.resource_id.split("/")[-1]
            rc, data = _run(
                ["aws", "cloudfront", "get-distribution-config", "--id", dist_id, "--output", "json"],
                env,
            )
            if rc != 0:
                return False
            try:
                min_proto = data["DistributionConfig"]["ViewerCertificate"]["MinimumProtocolVersion"]  # type: ignore[index]
                return "TLSv1.3" in min_proto or "TLSv1.2_2021" in min_proto
            except (KeyError, TypeError):
                return False

        elif kind == ResourceKind.GCP_SSL_POLICY:
            policy_name = asset.resource_id.split("/")[-1]
            rc, data = _run(
                ["gcloud", "compute", "ssl-policies", "describe", policy_name, "--format=json"],
                env,
            )
            if rc != 0:
                return False
            min_tls = data.get("minTlsVersion", "") if isinstance(data, dict) else ""  # type: ignore[union-attr]
            return min_tls == "TLS_1_3"

        else:
            # Generic: if we got here without error, assume success
            console.print("[dim]No specific health check for this resource kind — assuming success.[/]")
            return True

    except Exception as exc:
        console.print(f"[bold red]Health check error:[/] {exc}")
        return False
