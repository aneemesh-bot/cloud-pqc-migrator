from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from cloud_pqc_migrator.discovery import run_aws_discovery
from cloud_pqc_migrator.execution.gate import run_approval_gate
from cloud_pqc_migrator.models import RemediationStatus
from cloud_pqc_migrator.triage import evaluate


# ── Shared fixture ────────────────────────────────────────────────────────────

@pytest.fixture
def known_remediation_json():
    return json.dumps({
        "cli_command": (
            "aws elbv2 modify-listener "
            "--listener-arn arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/prod-alb/abc/def "
            "--ssl-policy ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06 --output json"
        ),
        "rollback_command": (
            "aws elbv2 modify-listener "
            "--listener-arn arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/prod-alb/abc/def "
            "--ssl-policy ELBSecurityPolicy-2016-08 --output json"
        ),
        "iac_template": None,
        "forecasted_state": "TLS 1.3 enforced",
        "reasoning": "Upgrades to TLS 1.3 per FIPS 203.",
    })


# ── Test 1: full discover → triage pipeline ───────────────────────────────────

def test_aws_discover_triage_pipeline(mock_creds):
    """Dry-run discovery → triage returns prioritised gaps sorted by priority."""
    cbom = run_aws_discovery(mock_creds, dry_run=True)
    gaps = evaluate(cbom)

    assert len(gaps) >= 1, "Mock data should produce at least one gap"
    priorities = [g.priority.value for g in gaps]
    assert priorities == sorted(priorities), "Gaps must be sorted priority-ascending (1=CRITICAL first)"
    assert any(g.priority.value <= 2 for g in gaps), "Mock TLS 1.2 ALB should produce CRITICAL or HIGH gap"


# ── Test 2: LLM remediation generation with mocked Anthropic client ───────────

def test_remediation_generation_with_mock_anthropic(mocker, sample_gap, known_remediation_json):
    """generate_remediation() wraps a valid LLM JSON response into a Remediation."""
    import cloud_pqc_migrator.remediation.llm_pipeline as pipeline
    pipeline._client = None  # reset module-level singleton

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=known_remediation_json)]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message

    mocker.patch.object(pipeline, "_get_client", return_value=mock_client)

    from cloud_pqc_migrator.remediation import generate_remediation
    remediation = generate_remediation(sample_gap)

    assert remediation.cli_command.startswith("aws elbv2 modify-listener")
    assert remediation.rollback_command.startswith("aws elbv2 modify-listener")
    assert remediation.status == RemediationStatus.PENDING
    assert remediation.gap is sample_gap


# ── Test 3: approval gate approve-then-skip flow ──────────────────────────────

def test_approval_gate_approve_then_skip(mock_creds, sample_remediation, sample_gap):
    """Approve first remediation (dry-run), skip second — verify statuses."""
    from cloud_pqc_migrator.models import Remediation

    rem2 = Remediation(
        remediation_id="test-id-002",
        gap=sample_gap,
        cli_command="aws elbv2 modify-listener --listener-arn arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/prod-alb/abc/def --ssl-policy ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06 --output json",
        rollback_command="aws elbv2 modify-listener --listener-arn arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/prod-alb/abc/def --ssl-policy ELBSecurityPolicy-2016-08 --output json",
        forecasted_state="TLS 1.3 enforced",
    )

    with patch("cloud_pqc_migrator.execution.gate._prompt_choice", side_effect=["approve", "skip"]):
        results = run_approval_gate([sample_remediation, rem2], mock_creds, dry_run=True)

    assert results[0].status == RemediationStatus.EXECUTED
    assert results[1].status == RemediationStatus.REJECTED


# ── Test 4: health check failure triggers rollback ────────────────────────────

def test_health_check_failure_triggers_rollback(mocker, mock_creds, sample_remediation):
    """When health check fails after execution, rollback fires and status is ROLLED_BACK."""
    mocker.patch(
        "cloud_pqc_migrator.execution.gate._execute_command",
        return_value=(True, "execution succeeded"),
    )
    mocker.patch(
        "cloud_pqc_migrator.execution.gate.run_health_check",
        return_value=False,
    )
    rollback_mock = mocker.patch(
        "cloud_pqc_migrator.execution.gate.execute_rollback",
        return_value=True,
    )

    with patch("cloud_pqc_migrator.execution.gate._prompt_choice", return_value="approve"):
        results = run_approval_gate([sample_remediation], mock_creds, dry_run=False)

    assert results[0].status == RemediationStatus.ROLLED_BACK
    rollback_mock.assert_called_once()
