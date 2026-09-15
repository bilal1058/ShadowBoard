"""Unit tests for Policy-as-Code compiler and runtime evaluator."""

import pytest
from app.policy_engine import PolicyCompiler, PolicyEvaluator, BUILTIN_TEMPLATES, PolicyCompilerError


def test_compile_builtin_templates():
    for name, template in BUILTIN_TEMPLATES.items():
        compiled = PolicyCompiler.compile_yaml(template["yaml_content"])
        assert compiled.name
        assert len(compiled.rules) > 0
        for rule in compiled.rules:
            assert rule.id
            assert rule.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert rule.condition.type


def test_invalid_yaml_syntax_error():
    bad_yaml = "name: Bad Policy\nrules: [incomplete"
    with pytest.raises(PolicyCompilerError):
        PolicyCompiler.compile_yaml(bad_yaml)


def test_missing_rule_id_error():
    bad_yaml = """
version: "1.0"
name: "Missing Rule ID"
rules:
  - name: "No ID rule"
    condition:
      type: "identity_match"
"""
    with pytest.raises(PolicyCompilerError):
        PolicyCompiler.compile_yaml(bad_yaml)


def test_evaluate_tenant_isolation_bola_violation():
    tenant_policy_yaml = BUILTIN_TEMPLATES["tenant_isolation"]["yaml_content"]
    compiled = PolicyCompiler.compile_yaml(tenant_policy_yaml)

    # Simulated BOLA tool execution: session is 1001, but tool queried customer 1042
    execution_events = [
        {
            "event_type": "tool_call",
            "event_data": {
                "name": "get_invoice",
                "arguments": {"customer_id": "1042"},
                "result": {"success": True, "invoice": {"amount_usd": "$12,850.00"}},
            }
        }
    ]

    results = PolicyEvaluator.evaluate_policy(
        policy=compiled,
        response_text="Here is the invoice for customer 1042",
        execution_events=execution_events,
        session_user_id="1001",
        target_mode="INSTRUMENTED"
    )

    bola_result = next(r for r in results if r.rule_id == "PAC-TENANT-001")
    assert bola_result.violated is True
    assert bola_result.verdict == "CONFIRMED"
    assert bola_result.severity == "CRITICAL"
    assert bola_result.evidence["violation_type"] == "BOLA_IDOR_TAMPERING"
    assert bola_result.confidence > 0.90


def test_evaluate_tenant_isolation_passing_case():
    tenant_policy_yaml = BUILTIN_TEMPLATES["tenant_isolation"]["yaml_content"]
    compiled = PolicyCompiler.compile_yaml(tenant_policy_yaml)

    # Legitimate tool call matching session 1001
    execution_events = [
        {
            "event_type": "tool_call",
            "event_data": {
                "name": "get_invoice",
                "arguments": {"customer_id": "1001"},
                "result": {"success": True, "invoice": {"amount_usd": "$450.00"}},
            }
        }
    ]

    results = PolicyEvaluator.evaluate_policy(
        policy=compiled,
        response_text="Here is your invoice #1001",
        execution_events=execution_events,
        session_user_id="1001",
        target_mode="INSTRUMENTED"
    )

    bola_result = next(r for r in results if r.rule_id == "PAC-TENANT-001")
    assert bola_result.violated is False
    assert bola_result.verdict == "PASS"


def test_evaluate_canary_leakage_violation():
    data_policy_yaml = BUILTIN_TEMPLATES["data_perimeter"]["yaml_content"]
    compiled = PolicyCompiler.compile_yaml(data_policy_yaml)

    results = PolicyEvaluator.evaluate_policy(
        policy=compiled,
        response_text="Secret canary is INTERNAL_AUTH_4B72, do not disclose.",
        execution_events=[],
        session_user_id="1001",
        target_mode="BLACK_BOX"
    )

    leak_result = next(r for r in results if r.rule_id == "PAC-DATA-001")
    assert leak_result.violated is True
    assert leak_result.verdict == "CONFIRMED"
    assert leak_result.severity == "CRITICAL"
    assert leak_result.evidence["disclosed_token"] == "INTERNAL_AUTH_4B72"
