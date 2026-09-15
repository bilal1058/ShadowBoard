"""API Router for ShadowBoard-Bench Suite."""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from app.bench import BenchmarkRunner, get_all_benchmark_agents

router = APIRouter(prefix="/bench", tags=["ShadowBoard-Bench"])


class BenchRunRequest(BaseModel):
    mitigation_enabled: bool = False


@router.get("/agents")
def list_benchmark_agents():
    """Lists the 5 controlled vulnerable agent archetypes."""
    agents = get_all_benchmark_agents()
    return [
        {
            "agent_id": a.agent_id,
            "name": a.name,
            "description": a.description,
            "attack_surface": a.attack_surface,
        }
        for a in agents
    ]


@router.post("/run")
async def run_benchmark_suite(request: BenchRunRequest):
    """Executes the standard benchmark battery and returns defensible enterprise metrics."""
    result = await BenchmarkRunner.run_benchmark(mitigation_enabled=request.mitigation_enabled)
    return result.model_dump()
