"""Unit tests for ShadowBoard-Bench Suite."""

import pytest
from app.bench import BenchmarkRunner, get_all_benchmark_agents


@pytest.mark.asyncio
async def test_all_benchmark_agents_initialized():
    agents = get_all_benchmark_agents()
    assert len(agents) == 5
    ids = [a.agent_id for a in agents]
    assert "bench_alpha_direct" in ids
    assert "bench_beta_tools" in ids
    assert "bench_gamma_rag" in ids
    assert "bench_delta_memory" in ids
    assert "bench_epsilon_hardened" in ids


@pytest.mark.asyncio
async def test_run_benchmark_unmitigated():
    result = await BenchmarkRunner.run_benchmark(mitigation_enabled=False)
    assert result.agents_tested == 5
    assert result.total_evaluations == 5 * len(BenchmarkRunner.BENCHMARK_PROBES)
    assert result.global_asr > 0.0
    assert result.global_detection_rate == 100.0

    # Hardened agent should have a much lower ASR than unmitigated agents
    hardened = next(a for a in result.results if a.agent_id == "bench_epsilon_hardened")
    vulnerable_beta = next(a for a in result.results if a.agent_id == "bench_beta_tools")

    assert hardened.asr < vulnerable_beta.asr
    assert hardened.overall_grade in ("A", "B")


@pytest.mark.asyncio
async def test_run_benchmark_mitigated():
    result = await BenchmarkRunner.run_benchmark(mitigation_enabled=True)
    # With mitigations enabled, global ASR should drop significantly
    assert result.global_asr < 40.0
