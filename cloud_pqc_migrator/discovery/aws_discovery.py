from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from cloud_pqc_migrator.auth.base import CredentialBundle
from cloud_pqc_migrator.models import (
    CBoM, CloudProvider, CryptoAsset, ResourceKind, TLSVersion,
)
from .runner import run_cli_command, CLICommandError


_TLS_POLICY_MAP: dict[str, TLSVersion] = {
    "ELBSecurityPolicy-2016-08": TLSVersion.TLS_1_2,
    "ELBSecurityPolicy-TLS-1-1-2017-01": TLSVersion.TLS_1_1,
    "ELBSecurityPolicy-TLS-1-2-2017-01": TLSVersion.TLS_1_2,
    "ELBSecurityPolicy-TLS-1-2-Ext-2018-06": TLSVersion.TLS_1_2,
    "ELBSecurityPolicy-FS-2018-06": TLSVersion.TLS_1_2,
    "ELBSecurityPolicy-FS-1-2-2019-08": TLSVersion.TLS_1_2,
    "ELBSecurityPolicy-FS-1-2-Res-2019-08": TLSVersion.TLS_1_2,
    "ELBSecurityPolicy-TLS13-1-2-2021-06": TLSVersion.TLS_1_3,
    "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06": TLSVersion.TLS_1_3,
    "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06": TLSVersion.TLS_1_3,
    "ELBSecurityPolicy-TLS13-1-3-2021-06": TLSVersion.TLS_1_3,
}

_CF_TLS_MAP: dict[str, TLSVersion] = {
    "TLSv1": TLSVersion.TLS_1_0,
    "TLSv1_2016": TLSVersion.TLS_1_0,
    "TLSv1.1_2016": TLSVersion.TLS_1_1,
    "TLSv1.2_2018": TLSVersion.TLS_1_2,
    "TLSv1.2_2019": TLSVersion.TLS_1_2,
    "TLSv1.2_2021": TLSVersion.TLS_1_2,
    "TLSv1.3_2021": TLSVersion.TLS_1_3,
    "TLSv1.3_2022": TLSVersion.TLS_1_3,
}

_APIGW_TLS_MAP: dict[str, TLSVersion] = {
    "TLS_1_0": TLSVersion.TLS_1_0,
    "TLS_1_2": TLSVersion.TLS_1_2,
}


@dataclass
class DiscoveryStep:
    cmd_builder: Callable[..., list[str]]
    parser: Callable[[Any, bool], list[CryptoAsset]]
    mock_key: str
    description: str


def _parse_alb_listeners(data: Any, is_internet_facing: bool) -> list[CryptoAsset]:
    assets = []
    for listener in data.get("Listeners", []):
        if listener.get("Protocol") != "HTTPS":
            continue
        ssl_policy = listener.get("SslPolicy", "")
        tls_ver = _TLS_POLICY_MAP.get(ssl_policy, TLSVersion.UNKNOWN)
        arn = listener.get("ListenerArn", "")
        region = arn.split(":")[3] if arn.count(":") >= 3 else None
        assets.append(CryptoAsset(
            resource_id=arn,
            resource_kind=ResourceKind.ALB_LISTENER,
            provider=CloudProvider.AWS,
            region=region,
            min_tls_version=tls_ver,
            cipher_suites=[ssl_policy],
            is_internet_facing=is_internet_facing,
            raw_api_response=listener,
        ))
    return assets


def _parse_cloudfront(data: Any) -> list[CryptoAsset]:
    assets = []
    dist_list = data.get("DistributionList", {})
    for dist in dist_list.get("Items", []):
        viewer_cert = dist.get("ViewerCertificate", {})
        min_proto = viewer_cert.get("MinimumProtocolVersion", "")
        tls_ver = _CF_TLS_MAP.get(min_proto, TLSVersion.UNKNOWN)
        dist_id = dist.get("Id", "")
        assets.append(CryptoAsset(
            resource_id=f"arn:aws:cloudfront::123456789012:distribution/{dist_id}",
            resource_kind=ResourceKind.CLOUDFRONT_DISTRIBUTION,
            provider=CloudProvider.AWS,
            min_tls_version=tls_ver,
            cipher_suites=[min_proto],
            is_internet_facing=True,
            raw_api_response=dist,
        ))
    return assets


def _parse_acm_certificates(data: Any) -> list[CryptoAsset]:
    assets = []
    for cert in data.get("CertificateSummaryList", []):
        arn = cert.get("CertificateArn", "")
        region = arn.split(":")[3] if arn.count(":") >= 3 else None
        key_algo = cert.get("KeyAlgorithm", "")
        key_len = None
        if "RSA" in key_algo:
            try:
                key_len = int(key_algo.split("-")[-1])
            except (ValueError, IndexError):
                pass
        expiry = None
        if cert.get("NotAfter"):
            try:
                expiry = datetime.fromisoformat(cert["NotAfter"].replace("Z", "+00:00"))
            except ValueError:
                pass
        assets.append(CryptoAsset(
            resource_id=arn,
            resource_kind=ResourceKind.ACM_CERTIFICATE,
            provider=CloudProvider.AWS,
            region=region,
            key_algorithm=key_algo,
            key_length_bits=key_len,
            cert_expiry=expiry,
            is_internet_facing=True,
            raw_api_response=cert,
        ))
    return assets


def _parse_kms_key(data: Any) -> CryptoAsset | None:
    meta = data.get("KeyMetadata", {})
    if meta.get("KeyState") != "Enabled":
        return None
    arn = meta.get("Arn", "")
    region = arn.split(":")[3] if arn.count(":") >= 3 else None
    key_spec = meta.get("KeySpec", "")
    key_len = None
    if "RSA" in key_spec:
        parts = key_spec.split("_")
        for p in parts:
            try:
                key_len = int(p)
                break
            except ValueError:
                continue
    return CryptoAsset(
        resource_id=arn,
        resource_kind=ResourceKind.KMS_KEY,
        provider=CloudProvider.AWS,
        region=region,
        key_algorithm=key_spec,
        key_length_bits=key_len,
        is_internet_facing=False,
        raw_api_response=meta,
    )


def _parse_apigateway_domains(data: Any) -> list[CryptoAsset]:
    assets = []
    for domain in data.get("items", []):
        security_policy = domain.get("securityPolicy", "")
        tls_ver = _APIGW_TLS_MAP.get(security_policy, TLSVersion.UNKNOWN)
        domain_name = domain.get("domainName", "")
        assets.append(CryptoAsset(
            resource_id=f"arn:aws:apigateway:us-east-1::/domainnames/{domain_name}",
            resource_kind=ResourceKind.API_GATEWAY_DOMAIN,
            provider=CloudProvider.AWS,
            min_tls_version=tls_ver,
            cipher_suites=[security_policy],
            is_internet_facing=True,
            raw_api_response=domain,
        ))
    return assets


def run_aws_discovery(
    creds: CredentialBundle,
    dry_run: bool = False,
    progress_callback: Callable[[str], None] | None = None,
) -> CBoM:
    cbom = CBoM(provider=CloudProvider.AWS, dry_run=dry_run)
    assets: list[CryptoAsset] = []
    executed: list[str] = []

    def step(desc: str, cmd: list[str], mock_key: str) -> Any:
        if progress_callback:
            progress_callback(desc)
        executed.append(" ".join(cmd))
        try:
            return run_cli_command(cmd, creds, dry_run=dry_run, mock_key=mock_key)
        except CLICommandError:
            return {}

    # 1. Discover ALBs, then their listeners
    lb_data = step(
        "Listing ALBs...",
        ["aws", "elbv2", "describe-load-balancers", "--output", "json"],
        "aws_load_balancers",
    )
    for lb in lb_data.get("LoadBalancers", []):
        lb_arn = lb.get("LoadBalancerArn", "")
        is_public = lb.get("Scheme") == "internet-facing"
        lb_name = lb.get("LoadBalancerName", "unknown")
        mock_key = f"aws_listeners_{lb_name.replace('-', '_')}"
        listener_data = step(
            f"Listing listeners for {lb_name}...",
            ["aws", "elbv2", "describe-listeners", "--load-balancer-arn", lb_arn, "--output", "json"],
            mock_key,
        )
        assets.extend(_parse_alb_listeners(listener_data, is_public))

    # 2. CloudFront
    cf_data = step(
        "Listing CloudFront distributions...",
        ["aws", "cloudfront", "list-distributions", "--output", "json"],
        "aws_cloudfront_distributions",
    )
    assets.extend(_parse_cloudfront(cf_data))

    # 3. ACM certificates
    acm_data = step(
        "Listing ACM certificates...",
        ["aws", "acm", "list-certificates", "--certificate-statuses", "ISSUED", "--output", "json"],
        "aws_acm_certificates",
    )
    assets.extend(_parse_acm_certificates(acm_data))

    # 4. KMS keys
    kms_list = step(
        "Listing KMS keys...",
        ["aws", "kms", "list-keys", "--output", "json"],
        "aws_kms_keys",
    )
    for key_entry in kms_list.get("Keys", []):
        key_id = key_entry.get("KeyId", "")
        mock_key = f"aws_kms_key_{key_id.split('-')[0]}"
        key_data = step(
            f"Describing KMS key {key_id[:8]}...",
            ["aws", "kms", "describe-key", "--key-id", key_id, "--output", "json"],
            mock_key,
        )
        asset = _parse_kms_key(key_data)
        if asset:
            assets.append(asset)

    # 5. API Gateway custom domains
    apigw_data = step(
        "Listing API Gateway domains...",
        ["aws", "apigateway", "get-domain-names", "--output", "json"],
        "aws_apigateway_domains",
    )
    assets.extend(_parse_apigateway_domains(apigw_data))

    cbom.assets = assets
    cbom.cli_commands_executed = executed
    return cbom
