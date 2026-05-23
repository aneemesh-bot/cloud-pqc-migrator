import pytest
from cloud_pqc_migrator.models import (
    CBoM, CryptoAsset, CloudProvider, TLSVersion, ResourceKind,
    Gap, Priority, FIPSStandard,
    Remediation, RemediationStatus,
)


@pytest.fixture
def alb_listener_tls12():
    return CryptoAsset(
        resource_id="arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/prod-alb/abc/def",
        resource_kind=ResourceKind.ALB_LISTENER,
        provider=CloudProvider.AWS,
        region="us-east-1",
        min_tls_version=TLSVersion.TLS_1_2,
        cipher_suites=["ELBSecurityPolicy-2016-08"],
        is_internet_facing=True,
        raw_api_response={
            "ListenerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/prod-alb/abc/def",
            "SslPolicy": "ELBSecurityPolicy-2016-08",
            "Protocol": "HTTPS",
        },
    )


@pytest.fixture
def alb_listener_tls13():
    return CryptoAsset(
        resource_id="arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/secure-alb/abc/def",
        resource_kind=ResourceKind.ALB_LISTENER,
        provider=CloudProvider.AWS,
        region="us-east-1",
        min_tls_version=TLSVersion.TLS_1_3,
        cipher_suites=["ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06"],
        is_internet_facing=True,
        raw_api_response={},
    )


@pytest.fixture
def kms_rsa_2048():
    return CryptoAsset(
        resource_id="arn:aws:kms:us-east-1:123456789012:key/aaaa1111-bbbb-2222-cccc-3333",
        resource_kind=ResourceKind.KMS_KEY,
        provider=CloudProvider.AWS,
        region="us-east-1",
        key_algorithm="RSA_2048",
        key_length_bits=2048,
        is_internet_facing=False,
        raw_api_response={"KeySpec": "RSA_2048", "KeyUsage": "ENCRYPT_DECRYPT"},
    )


@pytest.fixture
def gcp_ssl_policy_tls12():
    return CryptoAsset(
        resource_id="projects/my-project/global/sslPolicies/legacy-policy",
        resource_kind=ResourceKind.GCP_SSL_POLICY,
        provider=CloudProvider.GCP,
        min_tls_version=TLSVersion.TLS_1_2,
        cipher_suites=["TLS_RSA_WITH_AES_128_GCM_SHA256"],
        is_internet_facing=True,
        raw_api_response={"minTlsVersion": "TLS_1_2", "profile": "COMPATIBLE"},
    )


@pytest.fixture
def sample_cbom(alb_listener_tls12, kms_rsa_2048, gcp_ssl_policy_tls12):
    cbom = CBoM(provider=CloudProvider.AWS, dry_run=True)
    cbom.assets = [alb_listener_tls12, kms_rsa_2048]
    return cbom


@pytest.fixture
def sample_gap(alb_listener_tls12):
    return Gap(
        gap_id="abc123",
        asset=alb_listener_tls12,
        priority=Priority.CRITICAL,
        rule_id="tls.min_version",
        description="TLS 1.2 only",
        fips_references=[FIPSStandard.FIPS_203],
        current_state="TLS 1.2 only",
        target_state="TLS 1.3 + ML-KEM",
    )
