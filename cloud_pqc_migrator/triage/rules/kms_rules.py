from __future__ import annotations

import hashlib

from cloud_pqc_migrator.models import CryptoAsset, FIPSStandard, Gap, Priority, ResourceKind
from cloud_pqc_migrator.triage.timeline import default_t_start

_KMS_KINDS = {ResourceKind.KMS_KEY, ResourceKind.GCP_KMS_KEY, ResourceKind.ACM_CERTIFICATE}
_EC_WEAK_ALGORITHMS = {"EC_prime256v1", "EC-prime256v1", "EC_secp384r1", "EC-secp384r1"}


def _gap_id(asset_id: str, rule: str) -> str:
    return hashlib.md5(f"{asset_id}:{rule}".encode()).hexdigest()


def evaluate_kms(asset: CryptoAsset) -> list[Gap]:
    if asset.resource_kind not in _KMS_KINDS:
        return []

    gaps: list[Gap] = []
    algo = (asset.key_algorithm or "").upper()

    # Rule: RSA key too short
    if "RSA" in algo:
        key_len = asset.key_length_bits or 0
        if 0 < key_len < 3072:
            gaps.append(Gap(
                gap_id=_gap_id(asset.resource_id, "kms.rsa_key_short"),
                asset=asset,
                priority=Priority.HIGH,
                rule_id="kms.rsa_key_short",
                description=f"RSA {key_len}-bit key is below the FIPS 203/204 3072-bit minimum and is vulnerable to quantum decryption",
                fips_references=[FIPSStandard.FIPS_203, FIPSStandard.FIPS_204],
                current_state=f"RSA-{key_len} key ({asset.key_algorithm})",
                target_state="Migrate to ML-KEM-768 (FIPS 203) or RSA-3072+ as interim step; plan for ML-DSA (FIPS 204) for signatures",
                t_start=default_t_start(asset.is_internet_facing),
            ))

    # Rule: ECC key not on PQC migration path
    if any(weak in algo for weak in ("PRIME256", "P256", "SECP256", "SECP384", "P384")):
        gaps.append(Gap(
            gap_id=_gap_id(asset.resource_id, "kms.ec_not_pqc"),
            asset=asset,
            priority=Priority.CRITICAL if asset.is_internet_facing else Priority.HIGH,
            rule_id="kms.ec_not_pqc",
            description=f"Elliptic curve key ({asset.key_algorithm}) is vulnerable to Shor's algorithm on quantum computers",
            fips_references=[FIPSStandard.FIPS_203, FIPSStandard.FIPS_204],
            current_state=f"ECC key: {asset.key_algorithm}",
            target_state="Plan migration to ML-KEM-768 (key encapsulation) and ML-DSA-65 (signatures) per FIPS 203/204",
            t_start=default_t_start(asset.is_internet_facing),
        ))

    # Rule: symmetric keys are generally OK but flag if algorithm is unknown
    if algo in ("SYMMETRIC_DEFAULT", "AES_256", "AES_128") and not asset.is_internet_facing:
        pass  # AES-256 with symmetric keys is quantum-safe with doubled key space assumption

    return gaps
