from __future__ import annotations

import hashlib

from cloud_pqc_migrator.models import CryptoAsset, FIPSStandard, Gap, Priority, TLSVersion, ResourceKind
from cloud_pqc_migrator.triage.timeline import default_t_start

_DEPRECATED_CIPHERS = {
    "RC4", "DES", "3DES", "AES-CBC-SHA", "AES128-SHA", "AES256-SHA",
    "RC4-MD5", "DES-CBC3-SHA", "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
}

_PQC_CIPHER_KEYWORDS = {"ML-KEM", "Kyber", "X25519MLKEM768", "mlkem", "kyber"}

_TLS_1_3_POLICIES = {
    "ELBSecurityPolicy-TLS13-1-2-2021-06",
    "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
    "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
    "ELBSecurityPolicy-TLS13-1-3-2021-06",
}

_APPLICABLE_KINDS = {
    ResourceKind.ALB_LISTENER,
    ResourceKind.CLOUDFRONT_DISTRIBUTION,
    ResourceKind.API_GATEWAY_DOMAIN,
    ResourceKind.GCP_SSL_POLICY,
    ResourceKind.GCP_LB_TARGET_HTTPS_PROXY,
}


def _gap_id(asset_id: str, rule: str) -> str:
    return hashlib.md5(f"{asset_id}:{rule}".encode()).hexdigest()


def evaluate_tls(asset: CryptoAsset) -> list[Gap]:
    if asset.resource_kind not in _APPLICABLE_KINDS:
        return []

    gaps: list[Gap] = []

    # Rule: TLS minimum version check
    if asset.min_tls_version not in (TLSVersion.TLS_1_3, TLSVersion.UNKNOWN):
        if asset.min_tls_version in (TLSVersion.TLS_1_0, TLSVersion.TLS_1_1):
            priority = Priority.CRITICAL
            desc = f"Resource uses {asset.min_tls_version.value} — incapable of TLS 1.3 negotiation (zero crypto-agility)"
        else:
            priority = Priority.CRITICAL if not asset.is_internet_facing else Priority.HIGH
            desc = f"Resource enforces maximum {asset.min_tls_version.value}; TLS 1.3 required for PQC hybrid ciphers"

        gaps.append(Gap(
            gap_id=_gap_id(asset.resource_id, "tls.min_version"),
            asset=asset,
            priority=priority,
            rule_id="tls.min_version",
            description=desc,
            fips_references=[FIPSStandard.FIPS_203],
            current_state=f"Minimum TLS: {asset.min_tls_version.value}; cipher policy: {', '.join(asset.cipher_suites) or 'unknown'}",
            target_state="TLS 1.3 enforced with hybrid ML-KEM-768 (X25519MLKEM768) key agreement (FIPS 203 / CNSA 2.0)",
            t_start=default_t_start(asset.is_internet_facing),
        ))

    # Rule: deprecated ciphers
    bad_ciphers = [c for c in asset.cipher_suites if any(d in c for d in _DEPRECATED_CIPHERS)]
    if bad_ciphers:
        gaps.append(Gap(
            gap_id=_gap_id(asset.resource_id, "tls.deprecated_cipher"),
            asset=asset,
            priority=Priority.CRITICAL,
            rule_id="tls.deprecated_cipher",
            description=f"Deprecated cipher suites detected: {', '.join(bad_ciphers)}",
            fips_references=[FIPSStandard.FIPS_203, FIPSStandard.FIPS_204],
            current_state=f"Active deprecated ciphers: {', '.join(bad_ciphers)}",
            target_state="All deprecated ciphers removed; ECDHE + ML-KEM hybrid only",
            t_start=default_t_start(asset.is_internet_facing),
        ))

    # Rule: PQC cipher missing (only flag if we know the cipher list)
    if asset.cipher_suites and asset.min_tls_version == TLSVersion.TLS_1_3:
        has_pqc = any(kw.lower() in c.lower() for c in asset.cipher_suites for kw in _PQC_CIPHER_KEYWORDS)
        if not has_pqc:
            gaps.append(Gap(
                gap_id=_gap_id(asset.resource_id, "tls.pqc_cipher_missing"),
                asset=asset,
                priority=Priority.HIGH if asset.is_internet_facing else Priority.MEDIUM,
                rule_id="tls.pqc_cipher_missing",
                description="TLS 1.3 configured but no post-quantum key agreement cipher (ML-KEM/X25519MLKEM768) found",
                fips_references=[FIPSStandard.FIPS_203],
                current_state=f"TLS 1.3 ciphers: {', '.join(asset.cipher_suites)}",
                target_state="Hybrid PQC: X25519MLKEM768 added to cipher suite (FIPS 203 ML-KEM)",
                t_start=default_t_start(asset.is_internet_facing),
            ))

    return gaps
