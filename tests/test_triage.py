import pytest
from cloud_pqc_migrator.models import Priority, TLSVersion, FIPSStandard
from cloud_pqc_migrator.triage.rules.tls_rules import evaluate_tls
from cloud_pqc_migrator.triage.rules.kms_rules import evaluate_kms
from cloud_pqc_migrator.triage.engine import evaluate


def test_tls_rule_flags_tls12_listener(alb_listener_tls12):
    gaps = evaluate_tls(alb_listener_tls12)
    assert len(gaps) >= 1
    gap = gaps[0]
    assert gap.priority in (Priority.CRITICAL, Priority.HIGH)
    assert FIPSStandard.FIPS_203 in gap.fips_references


def test_tls_rule_no_gap_for_tls13(alb_listener_tls13):
    gaps = evaluate_tls(alb_listener_tls13)
    # TLS 1.3 should not produce a min_version gap
    version_gaps = [g for g in gaps if g.rule_id == "tls.min_version"]
    assert len(version_gaps) == 0


def test_kms_rule_flags_rsa_2048(kms_rsa_2048):
    gaps = evaluate_kms(kms_rsa_2048)
    assert len(gaps) >= 1
    gap = gaps[0]
    assert gap.priority == Priority.HIGH
    assert gap.rule_id == "kms.rsa_key_short"
    assert FIPSStandard.FIPS_203 in gap.fips_references


def test_engine_returns_sorted_gaps(sample_cbom):
    gaps = evaluate(sample_cbom)
    assert len(gaps) >= 1
    priorities = [g.priority.value for g in gaps]
    assert priorities == sorted(priorities)


def test_engine_deduplicates_gaps(alb_listener_tls12):
    from cloud_pqc_migrator.models import CBoM, CloudProvider
    cbom = CBoM(provider=CloudProvider.AWS, dry_run=True)
    cbom.assets = [alb_listener_tls12, alb_listener_tls12]  # duplicate asset
    gaps = evaluate(cbom)
    gap_ids = [g.gap_id for g in gaps]
    assert len(gap_ids) == len(set(gap_ids))


def test_tls_rule_flags_gcp_tls12(gcp_ssl_policy_tls12):
    gaps = evaluate_tls(gcp_ssl_policy_tls12)
    assert any(g.rule_id == "tls.min_version" for g in gaps)


def test_t_start_is_computed(alb_listener_tls12):
    gaps = evaluate_tls(alb_listener_tls12)
    for g in gaps:
        if g.rule_id == "tls.min_version":
            assert g.t_start is not None
            from datetime import date
            assert g.t_start < date(2030, 1, 1)
