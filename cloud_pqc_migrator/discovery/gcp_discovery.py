from __future__ import annotations

from typing import Any, Callable

from cloud_pqc_migrator.auth.base import CredentialBundle
from cloud_pqc_migrator.models import (
    CBoM, CloudProvider, CryptoAsset, ResourceKind, TLSVersion,
)
from .runner import run_cli_command, CLICommandError


_GCP_TLS_MAP: dict[str, TLSVersion] = {
    "TLS_1_0": TLSVersion.TLS_1_0,
    "TLS_1_1": TLSVersion.TLS_1_1,
    "TLS_1_2": TLSVersion.TLS_1_2,
    "TLS_1_3": TLSVersion.TLS_1_3,
}


def _parse_ssl_policies(data: Any) -> list[CryptoAsset]:
    assets = []
    if not isinstance(data, list):
        return assets
    for policy in data:
        name = policy.get("name", "")
        min_tls_raw = policy.get("minTlsVersion", "")
        tls_ver = _GCP_TLS_MAP.get(min_tls_raw, TLSVersion.UNKNOWN)
        ciphers = policy.get("enabledFeatures", [])
        assets.append(CryptoAsset(
            resource_id=name,
            resource_kind=ResourceKind.GCP_SSL_POLICY,
            provider=CloudProvider.GCP,
            min_tls_version=tls_ver,
            cipher_suites=ciphers,
            is_internet_facing=True,
            raw_api_response=policy,
        ))
    return assets


def _parse_certificates(data: Any) -> list[CryptoAsset]:
    assets = []
    if not isinstance(data, list):
        return assets
    for cert in data:
        name = cert.get("name", "")
        assets.append(CryptoAsset(
            resource_id=name,
            resource_kind=ResourceKind.GCP_CERTIFICATE,
            provider=CloudProvider.GCP,
            is_internet_facing=True,
            raw_api_response=cert,
        ))
    return assets


def _parse_kms_keys(data: Any) -> list[CryptoAsset]:
    assets = []
    if not isinstance(data, list):
        return assets
    for key in data:
        name = key.get("name", "")
        primary = key.get("primary", {})
        algorithm = primary.get("algorithm", key.get("versionTemplate", {}).get("algorithm", ""))
        key_len = None
        if "2048" in algorithm:
            key_len = 2048
        elif "3072" in algorithm:
            key_len = 3072
        elif "4096" in algorithm:
            key_len = 4096
        assets.append(CryptoAsset(
            resource_id=name,
            resource_kind=ResourceKind.GCP_KMS_KEY,
            provider=CloudProvider.GCP,
            key_algorithm=algorithm,
            key_length_bits=key_len,
            is_internet_facing=False,
            raw_api_response=key,
        ))
    return assets


def _parse_https_proxies(data: Any) -> list[CryptoAsset]:
    assets = []
    if not isinstance(data, list):
        return assets
    for proxy in data:
        name = proxy.get("name", "")
        assets.append(CryptoAsset(
            resource_id=name,
            resource_kind=ResourceKind.GCP_LB_TARGET_HTTPS_PROXY,
            provider=CloudProvider.GCP,
            is_internet_facing=True,
            raw_api_response=proxy,
        ))
    return assets


def run_gcp_discovery(
    creds: CredentialBundle,
    dry_run: bool = False,
    progress_callback: Callable[[str], None] | None = None,
) -> CBoM:
    cbom = CBoM(provider=CloudProvider.GCP, dry_run=dry_run)
    assets: list[CryptoAsset] = []
    executed: list[str] = []

    def step(desc: str, cmd: list[str], mock_key: str) -> Any:
        if progress_callback:
            progress_callback(desc)
        executed.append(" ".join(cmd))
        try:
            return run_cli_command(cmd, creds, dry_run=dry_run, mock_key=mock_key)
        except CLICommandError:
            return []

    ssl_data = step(
        "Listing GCP SSL policies...",
        ["gcloud", "compute", "ssl-policies", "list", "--format=json"],
        "gcp_ssl_policies",
    )
    assets.extend(_parse_ssl_policies(ssl_data))

    cert_data = step(
        "Listing GCP certificates...",
        ["gcloud", "certificate-manager", "certificates", "list", "--format=json"],
        "gcp_certificates",
    )
    assets.extend(_parse_certificates(cert_data))

    kms_data = step(
        "Listing GCP KMS keys...",
        ["gcloud", "kms", "keys", "list", "--location=-", "--format=json"],
        "gcp_kms_keys",
    )
    assets.extend(_parse_kms_keys(kms_data))

    proxy_data = step(
        "Listing GCP target HTTPS proxies...",
        ["gcloud", "compute", "target-https-proxies", "list", "--format=json"],
        "gcp_target_https_proxies",
    )
    assets.extend(_parse_https_proxies(proxy_data))

    cbom.assets = assets
    cbom.cli_commands_executed = executed
    return cbom
