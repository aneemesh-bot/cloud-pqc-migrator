from unittest.mock import patch
from cloud_pqc_migrator.models import Remediation, RemediationStatus
from cloud_pqc_migrator.execution.gate import run_approval_gate


def test_dry_run_approve_sets_executed(mock_creds, sample_remediation):
    with patch("cloud_pqc_migrator.execution.gate._prompt_choice", return_value="approve"):
        result = run_approval_gate([sample_remediation], mock_creds, dry_run=True)
    assert result[0].status == RemediationStatus.EXECUTED


def test_skip_sets_rejected(mock_creds, sample_remediation):
    with patch("cloud_pqc_migrator.execution.gate._prompt_choice", return_value="skip"):
        result = run_approval_gate([sample_remediation], mock_creds, dry_run=True)
    assert result[0].status == RemediationStatus.REJECTED


def test_quit_stops_processing(mock_creds, sample_remediation, sample_gap):
    rem2 = Remediation(
        remediation_id="test-id-002",
        gap=sample_gap,
        cli_command="aws elbv2 modify-listener --output json",
        rollback_command="aws elbv2 modify-listener --output json",
        forecasted_state="TLS 1.3",
    )
    with patch("cloud_pqc_migrator.execution.gate._prompt_choice", side_effect=["quit"]):
        result = run_approval_gate([sample_remediation, rem2], mock_creds, dry_run=True)
    # Both should remain PENDING because we quit before processing any
    assert all(r.status == RemediationStatus.PENDING for r in result)
