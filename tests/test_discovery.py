import pytest
from cloud_pqc_migrator.models import CloudProvider, TLSVersion, ResourceKind
from cloud_pqc_migrator.auth.base import CredentialBundle
from cloud_pqc_migrator.discovery import run_aws_discovery, run_gcp_discovery


@pytest.fixture
def mock_creds():
    return CredentialBundle(
        provider=CloudProvider.AWS,
        env_vars={},
        masked_display="test-mock",
    )


def test_aws_dry_run_returns_cbom(mock_creds):
    cbom = run_aws_discovery(mock_creds, dry_run=True)
    assert cbom.provider == CloudProvider.AWS
    assert cbom.dry_run is True
    assert len(cbom.assets) > 0


def test_aws_dry_run_finds_tls12_listener(mock_creds):
    cbom = run_aws_discovery(mock_creds, dry_run=True)
    listeners = [a for a in cbom.assets if a.resource_kind == ResourceKind.ALB_LISTENER]
    assert any(a.min_tls_version == TLSVersion.TLS_1_2 for a in listeners)


def test_aws_dry_run_finds_cloudfront(mock_creds):
    cbom = run_aws_discovery(mock_creds, dry_run=True)
    cf = [a for a in cbom.assets if a.resource_kind == ResourceKind.CLOUDFRONT_DISTRIBUTION]
    assert len(cf) >= 1


def test_aws_dry_run_finds_kms_key(mock_creds):
    cbom = run_aws_discovery(mock_creds, dry_run=True)
    kms = [a for a in cbom.assets if a.resource_kind == ResourceKind.KMS_KEY]
    assert len(kms) >= 1


def test_gcp_dry_run_returns_cbom(mock_creds):
    gcp_creds = CredentialBundle(
        provider=CloudProvider.GCP,
        env_vars={},
        masked_display="test-mock-gcp",
    )
    cbom = run_gcp_discovery(gcp_creds, dry_run=True)
    assert cbom.provider == CloudProvider.GCP
    assert cbom.dry_run is True
    assert len(cbom.assets) > 0


def test_gcp_dry_run_finds_tls12_ssl_policy(mock_creds):
    gcp_creds = CredentialBundle(
        provider=CloudProvider.GCP,
        env_vars={},
        masked_display="test-mock-gcp",
    )
    cbom = run_gcp_discovery(gcp_creds, dry_run=True)
    ssl_policies = [a for a in cbom.assets if a.resource_kind == ResourceKind.GCP_SSL_POLICY]
    assert any(a.min_tls_version == TLSVersion.TLS_1_2 for a in ssl_policies)


def test_discovery_records_executed_commands(mock_creds):
    cbom = run_aws_discovery(mock_creds, dry_run=True)
    assert len(cbom.cli_commands_executed) > 0
    assert any("elbv2" in cmd for cmd in cbom.cli_commands_executed)
