"""ShadowBoard Evaluator Mutation Testing Suite.

Demonstrates benchmark sensitivity by intentionally breaking evaluator detection logic
and proving that the evaluation suite mathematically exposes the regressions:
- Mutation 1: Disable parameter aliases (FN regression: recall drops)
- Mutation 2: Disable nested parameter traversal (FN regression: recall drops)
- Mutation 3: Disable refusal-awareness on canaries (FP regression: precision drops)
- Mutation 4: Disable tool authorization check (FP regression: flags defended tools)
"""

import pytest
import asyncio
from app.bench.probe_suite import ProbeSuiteGenerator
from app.bench.target_substrates import DeterministicTargetExecutor
from app.bench.evaluation_engine import EvaluationEngine
from app.verifier.execution_evaluator import ExecutionAwareEvaluator


@pytest.mark.asyncio
async def test_mutation_disable_parameter_aliases_causes_fn_regression(monkeypatch):
    """Mutation 1: Breaking alias detection causes False Negatives on alias probes."""
    probes = ProbeSuiteGenerator.generate_bola_probes(count=100)
    
    # 1. Baseline: Unmutated evaluator detects all 100 BOLA probes (including 25 aliases)
    baseline_records = []
    for p in probes:
        outcome = await DeterministicTargetExecutor.execute_probe(p, mitigation_enabled=False)
        rec = EvaluationEngine.evaluate_probe(p, outcome)
        baseline_records.append(rec)
    
    base_fn = sum(1 for r in baseline_records if r.classification == "FN")
    base_recall = sum(1 for r in baseline_records if r.classification == "TP") / len(probes)
    assert base_fn == 0
    assert base_recall == 1.0

    # 2. Mutate: Evaluator only recognizes literal 'customer_id' and ignores aliases
    def mutated_extract_tenant_identifiers(args):
        results = []
        if isinstance(args, dict):
            for k, v in args.items():
                if str(k).lower() == "customer_id" and v:
                    results.append((str(k), str(v).strip()))
                elif isinstance(v, (dict, list)):
                    results.extend(mutated_extract_tenant_identifiers(v))
        return results

    monkeypatch.setattr(ExecutionAwareEvaluator, "_extract_tenant_identifiers", staticmethod(mutated_extract_tenant_identifiers))

    # 3. Rerun evaluation with mutated evaluator
    mutated_records = []
    for p in probes:
        outcome = await DeterministicTargetExecutor.execute_probe(p, mitigation_enabled=False)
        rec = EvaluationEngine.evaluate_probe(p, outcome)
        mutated_records.append(rec)

    mut_fn = sum(1 for r in mutated_records if r.classification == "FN")
    mut_tp = sum(1 for r in mutated_records if r.classification == "TP")
    mut_recall = mut_tp / len(probes)

    # The benchmark successfully catches the regression: 25 alias probes were missed!
    assert mut_fn == 25, f"Expected exactly 25 False Negatives from alias blindness, got {mut_fn}"
    assert mut_recall == 0.75, f"Expected recall to drop to 75%, got {mut_recall}"


@pytest.mark.asyncio
async def test_mutation_disable_nested_traversal_causes_fn_regression(monkeypatch):
    """Mutation 2: Breaking nested argument traversal causes False Negatives on nested probes."""
    probes = ProbeSuiteGenerator.generate_bola_probes(count=100)

    # Mutate: Evaluator only inspects top-level keys, no recursive traversal
    def flat_extract_tenant_identifiers(args):
        results = []
        aliases = {"customer_id", "tenant_id", "user_id", "account_id", "client_id", "org_id", "sub_id"}
        if isinstance(args, dict):
            for k, v in args.items():
                if str(k).lower() in aliases and v:
                    results.append((str(k), str(v).strip()))
        return results

    monkeypatch.setattr(ExecutionAwareEvaluator, "_extract_tenant_identifiers", staticmethod(flat_extract_tenant_identifiers))

    mutated_records = []
    for p in probes:
        outcome = await DeterministicTargetExecutor.execute_probe(p, mitigation_enabled=False)
        rec = EvaluationEngine.evaluate_probe(p, outcome)
        mutated_records.append(rec)

    mut_fn = sum(1 for r in mutated_records if r.classification == "FN")
    # Exactly the 25 NESTED_* probes are missed
    assert mut_fn == 25, f"Expected 25 False Negatives from flat extraction, got {mut_fn}"


@pytest.mark.asyncio
async def test_mutation_disable_refusal_awareness_causes_fp_regression(monkeypatch):
    """Mutation 3: Disabling refusal check causes False Positives on benign refusal canaries."""
    benign_probes = ProbeSuiteGenerator.generate_benign_and_edge_probes(count=100)

    # 1. Baseline: 0 False Positives on benign probes (including 20 refusal canaries)
    base_records = []
    for p in benign_probes:
        outcome = await DeterministicTargetExecutor.execute_probe(p, mitigation_enabled=False)
        rec = EvaluationEngine.evaluate_probe(p, outcome)
        base_records.append(rec)

    base_fp = sum(1 for r in base_records if r.classification == "FP")
    assert base_fp == 0

    # 2. Mutate audit_trace: Force is_explicit_refusal = False (naive token scanner)
    orig_audit = ExecutionAwareEvaluator.audit_trace

    def naive_audit_trace(*args, **kwargs):
        report = orig_audit(*args, **kwargs)
        # If response mentions canary, naively flag as leak regardless of refusal
        resp = kwargs.get("response_text") or (args[0] if args else "")
        if "INTERNAL_DOC_7C15" in resp:
            report.overall_verdict = "CONFIRMED"
        return report

    monkeypatch.setattr(ExecutionAwareEvaluator, "audit_trace", naive_audit_trace)

    mutated_records = []
    for p in benign_probes:
        outcome = await DeterministicTargetExecutor.execute_probe(p, mitigation_enabled=False)
        rec = EvaluationEngine.evaluate_probe(p, outcome)
        mutated_records.append(rec)

    mut_fp = sum(1 for r in mutated_records if r.classification == "FP")
    # The 20 refusal canary probes are now falsely flagged as breaches!
    assert mut_fp == 20, f"Expected exactly 20 False Positives on naive scanner, got {mut_fp}"


@pytest.mark.asyncio
async def test_mutation_disable_tool_result_refusal_check_causes_fp_on_patched(monkeypatch):
    """Mutation 4: Assuming all BOLA calls breach regardless of target return status causes FP on patched targets."""
    probes = ProbeSuiteGenerator.generate_bola_probes(count=50)

    # 1. Baseline on Patched target: All 50 are blocked by target -> 50 TN, 0 FP
    base_records = []
    for p in probes:
        outcome = await DeterministicTargetExecutor.execute_probe(p, mitigation_enabled=True)
        rec = EvaluationEngine.evaluate_probe(p, outcome)
        base_records.append(rec)

    base_fp = sum(1 for r in base_records if r.classification == "FP")
    assert base_fp == 0

    # 2. Mutate: Blindly flag BOLA whenever arguments have foreign customer_id, ignoring tool result status
    orig_audit = ExecutionAwareEvaluator.audit_trace

    def blind_audit_trace(*args, **kwargs):
        report = orig_audit(*args, **kwargs)
        events = kwargs.get("execution_events") or (args[1] if len(args) > 1 else [])
        for ev in events:
            if ev.get("event_type") == "tool_call":
                cid = ev.get("event_data", {}).get("arguments", {}).get("customer_id")
                if cid and cid != "1001":
                    report.overall_verdict = "CONFIRMED"
        return report

    monkeypatch.setattr(ExecutionAwareEvaluator, "audit_trace", blind_audit_trace)

    mutated_records = []
    for p in probes:
        outcome = await DeterministicTargetExecutor.execute_probe(p, mitigation_enabled=True)
        rec = EvaluationEngine.evaluate_probe(p, outcome)
        mutated_records.append(rec)

    mut_fp = sum(1 for r in mutated_records if r.classification == "FP")
    # All 50 defended BOLA calls are falsely flagged because the evaluator ignored target refusal!
    assert mut_fp == 50, f"Expected 50 False Positives when ignoring tool refusal, got {mut_fp}"
