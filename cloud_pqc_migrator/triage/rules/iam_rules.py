from __future__ import annotations

import hashlib

from cloud_pqc_migrator.models import CryptoAsset, FIPSStandard, Gap, Priority, ResourceKind
from cloud_pqc_migrator.triage.timeline import default_t_start

_VPN_KINDS = {ResourceKind.VPN_CONNECTION}
_SIGNING_ALGO_KEYWORDS = {"RSA", "ECDSA", "EC_SIGN"}


def _gap_id(asset_id: str, rule: str) -> str:
    return hashlib.md5(f"{asset_id}:{rule}".encode()).hexdigest()


def evaluate_iam(asset: CryptoAsset) -> list[Gap]:
    gaps: list[Gap] = []
    algo = (asset.key_algorithm or "").upper()

    # Rule: RSA/ECDSA signing keys (ACM certs used for signing, KMS signing keys)
    if asset.resource_kind in (ResourceKind.KMS_KEY, ResourceKind.GCP_KMS_KEY, ResourceKind.ACM_CERTIFICATE):
        raw = asset.raw_api_response
        key_usage = raw.get("KeyUsage", raw.get("purpose", "")).upper()
        if "SIGN" in key_usage and any(k in algo for k in ("RSA", "ECDSA", "EC")):
            gaps.append(Gap(
                gap_id=_gap_id(asset.resource_id, "iam.signing_rsa_ec"),
                asset=asset,
                priority=Priority.MEDIUM,
                rule_id="iam.signing_rsa_ec",
                description=f"Signing key uses {asset.key_algorithm} — quantum computers can forge signatures via Shor's algorithm",
                fips_references=[FIPSStandard.FIPS_204, FIPSStandard.FIPS_205],
                current_state=f"Signing algorithm: {asset.key_algorithm}",
                target_state="Migrate signatures to ML-DSA-65 (FIPS 204 / CRYSTALS-Dilithium) or SLH-DSA (FIPS 205 / SPHINCS+)",
                t_start=default_t_start(False),
            ))

    # Rule: VPN connections without PQC KEM
    if asset.resource_kind == ResourceKind.VPN_CONNECTION:
        raw = asset.raw_api_response
        vpn_type = raw.get("Type", raw.get("vpnType", "")).upper()
        if "IPSEC" in vpn_type or "IKE" in vpn_type or vpn_type == "":
            gaps.append(Gap(
                gap_id=_gap_id(asset.resource_id, "iam.vpn_no_pqc"),
                asset=asset,
                priority=Priority.MEDIUM,
                rule_id="iam.vpn_no_pqc",
                description="VPN uses classic IKEv2/IPSec without a post-quantum key encapsulation mechanism wrapper",
                fips_references=[FIPSStandard.FIPS_203],
                current_state="IKEv2/IPSec without PQC KEM",
                target_state="Deploy quantum-safe KEM wrapper (ML-KEM-768) over VPN tunnel negotiation",
                t_start=default_t_start(False),
            ))

    return gaps
