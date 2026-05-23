import pytest
from cloud_pqc_migrator.remediation.validator import (
    validate_remediation_output,
    strip_markdown_fences,
    RemediationValidationError,
)


def test_strip_markdown_fences_json():
    text = '```json\n{"key": "value"}\n```'
    assert strip_markdown_fences(text) == '{"key": "value"}'


def test_strip_markdown_fences_bare():
    text = '{"key": "value"}'
    assert strip_markdown_fences(text) == '{"key": "value"}'


def test_validate_good_output():
    raw = """{
  "cli_command": "aws elbv2 modify-listener --listener-arn arn:aws:elasticloadbalancing:us-east-1:123:listener/abc --ssl-policy ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06 --output json",
  "rollback_command": "aws elbv2 modify-listener --listener-arn arn:aws:elasticloadbalancing:us-east-1:123:listener/abc --ssl-policy ELBSecurityPolicy-2016-08 --output json",
  "iac_template": null,
  "forecasted_state": "TLS 1.3 enforced with hybrid ML-KEM-768",
  "reasoning": "This upgrades to TLS 1.3 satisfying FIPS 203."
}"""
    data = validate_remediation_output(raw)
    assert data["cli_command"].startswith("aws ")
    assert data["rollback_command"].startswith("aws ")


def test_validate_rejects_shell_metachar():
    raw = """{
  "cli_command": "aws elbv2 describe-listeners; rm -rf /",
  "rollback_command": "aws elbv2 modify-listener --output json",
  "iac_template": null,
  "forecasted_state": "OK",
  "reasoning": "test"
}"""
    with pytest.raises(RemediationValidationError, match="metacharacters"):
        validate_remediation_output(raw)


def test_validate_rejects_wrong_prefix():
    raw = """{
  "cli_command": "bash -c 'rm -rf /'",
  "rollback_command": "aws elbv2 modify-listener --output json",
  "iac_template": null,
  "forecasted_state": "OK",
  "reasoning": "test"
}"""
    with pytest.raises(RemediationValidationError, match="must start with"):
        validate_remediation_output(raw)


def test_validate_rejects_missing_keys():
    raw = '{"cli_command": "aws sts get-caller-identity"}'
    with pytest.raises(RemediationValidationError, match="missing required keys"):
        validate_remediation_output(raw)


def test_validate_strips_fences_and_parses():
    raw = """```json
{
  "cli_command": "gcloud compute ssl-policies update my-policy --min-tls-version TLS_1_3 --format=json",
  "rollback_command": "gcloud compute ssl-policies update my-policy --min-tls-version TLS_1_2 --format=json",
  "iac_template": null,
  "forecasted_state": "TLS 1.3 enforced",
  "reasoning": "Upgrades GCP SSL policy to TLS 1.3."
}
```"""
    data = validate_remediation_output(raw)
    assert data["cli_command"].startswith("gcloud ")
