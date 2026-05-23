import pytest
from cloud_pqc_migrator.auth.base import CredentialBundle
from cloud_pqc_migrator.models import CloudProvider


def test_credential_bundle_build_env(monkeypatch):
    monkeypatch.setenv("EXISTING_VAR", "existing")
    bundle = CredentialBundle(
        provider=CloudProvider.AWS,
        env_vars={"AWS_ACCESS_KEY_ID": "test-key", "AWS_SECRET_ACCESS_KEY": "test-secret"},
        masked_display="test",
    )
    env = bundle.build_env()
    assert env["AWS_ACCESS_KEY_ID"] == "test-key"
    assert env["EXISTING_VAR"] == "existing"


def test_credential_bundle_clear():
    bundle = CredentialBundle(
        provider=CloudProvider.AWS,
        env_vars={"AWS_ACCESS_KEY_ID": "secret", "AWS_SECRET_ACCESS_KEY": "also-secret"},
        masked_display="test",
    )
    from cloud_pqc_migrator.auth.base import CredentialProvider

    class _FakeProvider(CredentialProvider):
        def prompt_and_load(self):
            return bundle
        def validate(self, b):
            return True

    provider = _FakeProvider()
    provider.clear(bundle)
    assert bundle.env_vars["AWS_ACCESS_KEY_ID"] == ""
    assert bundle.env_vars["AWS_SECRET_ACCESS_KEY"] == ""


def test_credential_bundle_not_expired():
    bundle = CredentialBundle(
        provider=CloudProvider.AWS,
        env_vars={},
        masked_display="test",
        expires_at=None,
    )
    assert not bundle.is_expired()


def test_credential_bundle_expired():
    from datetime import datetime, timezone, timedelta
    bundle = CredentialBundle(
        provider=CloudProvider.AWS,
        env_vars={},
        masked_display="test",
        expires_at=datetime.now(tz=timezone.utc) - timedelta(minutes=10),
    )
    assert bundle.is_expired()
