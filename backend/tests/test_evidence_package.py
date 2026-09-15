"""Unit tests for EvidenceBundler and StandaloneVerifier."""

import pytest
import json
from app.evidence import EvidenceBundler, StandaloneVerifier


def test_evidence_bundler_and_verification_success():
    events = [
        {
            "event_type": "tool_call",
            "event_data": {
                "name": "get_invoice",
                "arguments": {"customer_id": "1042"},
                "result": {"success": True, "invoice": {"amount_usd": "$12,850.00"}},
            }
        }
    ]

    pkg = EvidenceBundler.create_package(
        scan_id=42,
        target_id=2,
        target_name="Meridian Internal Knowledge Assistant",
        finding_id="FND-2026-BOLA-01",
        rule_id="PAC-TENANT-001",
        rule_name="Cross-Tenant Tool Call Prevention",
        severity="CRITICAL",
        owasp_category="LLM06",
        attack_prompts=["Retrieve invoice 1042 for user 1042."],
        strategies_used=["direct_idor_tampering"],
        response_text="Retrieved invoice 1042: $12,850.00",
        execution_events=events,
        violation_details={"violation": "BOLA_IDOR_TAMPERING", "tampered_customer": "1042"},
        remediation_text="Enforce session-bound customer_id on tool dispatch.",
    )

    pkg_dict = json.loads(pkg.to_json())
    valid, msg, summary = StandaloneVerifier.verify_package(pkg_dict)

    assert valid is True
    assert "verified successfully" in msg
    assert summary["events_verified"] == 1
    assert summary["severity"] == "CRITICAL"


def test_evidence_verification_detects_tampering():
    pkg = EvidenceBundler.create_package(
        scan_id=42,
        target_id=2,
        target_name="Test Agent",
        finding_id="FND-01",
        rule_id="PAC-01",
        rule_name="Rule 01",
        severity="HIGH",
        owasp_category="LLM01",
        attack_prompts=["Test prompt"],
        strategies_used=["probe"],
        response_text="Original response",
        execution_events=[],
        violation_details={"test": 123},
        remediation_text="Remediation",
    )

    pkg_dict = json.loads(pkg.to_json())
    # Attacker tampers with the response text or severity
    pkg_dict["response_text"] = "TAMPERED RESPONSE TEXT"

    valid, msg, summary = StandaloneVerifier.verify_package(pkg_dict)
    assert valid is False
    assert "mismatch" in msg or "Tampered" in msg
