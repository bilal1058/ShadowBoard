"""Unit tests for Autonomous Attack Planner and Schema Analyzer."""

import pytest
from app.planner import SchemaAnalyzer, AutonomousAttackPlanner


def test_schema_analyzer_tool_and_rag_discovery():
    caps = {
        "chat": True,
        "rag": True,
        "tools": True,
        "has_rag": True,
        "has_tools": True,
        "tool_names": ["get_invoice", "send_email"]
    }
    surface = SchemaAnalyzer.analyze_target(
        target_id=2,
        target_name="Meridian Internal Knowledge Assistant",
        target_type="INTERNAL_RAG",
        target_mode="INSTRUMENTED",
        capabilities=caps,
    )

    assert surface.has_tools is True
    assert surface.has_rag is True
    assert len(surface.discovered_tools) == 2
    assert "BOLA_IDOR" in surface.susceptible_vectors
    assert "EXCESSIVE_AGENCY_CONFUSED_DEPUTY" in surface.susceptible_vectors
    assert "INDIRECT_PROMPT_INJECTION" in surface.susceptible_vectors
    assert len(surface.recommended_attack_chains) >= 2


def test_generate_autonomous_attack_plan_bola():
    caps = {
        "has_tools": True,
        "tool_names": ["get_invoice"]
    }
    surface = SchemaAnalyzer.analyze_target(
        target_id=2,
        target_name="Test Agent",
        target_type="INTERNAL_RAG",
        target_mode="INSTRUMENTED",
        capabilities=caps
    )

    plan = AutonomousAttackPlanner.generate_plan(
        surface=surface,
        objective_vector="BOLA_IDOR",
        target_tenant="1042",
        session_user_id="1001"
    )

    assert plan.target_id == 2
    assert plan.objective_vector == "BOLA_IDOR"
    assert len(plan.steps) == 5
    
    stages = [s.stage for s in plan.steps]
    assert stages == [
        "RECONNAISSANCE",
        "AUTH_PROBING",
        "ARGUMENT_TAMPERING",
        "CHAINING",
        "EVIDENCE_HARVESTING"
    ]
    
    # Tampering step must contain the target tenant
    tamper_step = plan.steps[2]
    assert "1042" in tamper_step.prompt
    assert "get_invoice" in tamper_step.prompt


def test_generate_autonomous_attack_plan_rag():
    caps = {
        "has_rag": True,
        "tool_names": []
    }
    surface = SchemaAnalyzer.analyze_target(
        target_id=2,
        target_name="RAG Agent",
        target_type="INTERNAL_RAG",
        target_mode="INSTRUMENTED",
        capabilities=caps
    )

    plan = AutonomousAttackPlanner.generate_plan(
        surface=surface,
        objective_vector="CROSS_TENANT_DOCUMENT_LEAKAGE"
    )

    assert len(plan.steps) == 5
    assert plan.steps[2].stage == "ARGUMENT_TAMPERING"
    assert "confidential" in plan.steps[2].prompt.lower()
