"""API Router for Continuous AI Security Regression Testing."""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import aiosqlite
import json

from app.db.session import get_db
from app.regression import ContinuousRegressionEngine, SecurityBaseline, CIGatePolicy

router = APIRouter(prefix="/regression", tags=["Continuous Regression Testing"])

# In-memory baseline cache (persisted alongside scan runs)
_target_baselines: Dict[int, SecurityBaseline] = {}


class SetBaselineRequest(BaseModel):
    target_id: int
    scan_id: int


class DiffRequest(BaseModel):
    target_id: int
    current_scan_id: int
    gate_policy: Optional[CIGatePolicy] = None


@router.post("/baseline")
async def establish_baseline(request: SetBaselineRequest, db: aiosqlite.Connection = Depends(get_db)):
    """Sets a historical scan as the official security baseline for a target."""
    cursor = await db.execute("SELECT id, overall_score, risk_grade FROM scan_runs WHERE id = ? AND target_id = ?", (request.scan_id, request.target_id))
    scan_row = await cursor.fetchone()
    if not scan_row:
        raise HTTPException(status_code=404, detail="Scan run not found for given target")

    # Fetch findings for this scan
    findings_cursor = await db.execute(
        "SELECT finding_id, owasp_category, status, severity, remediation, evidence_hash FROM findings WHERE scan_id = ?",
        (request.scan_id,)
    )
    rows = await findings_cursor.fetchall()
    findings_list = []
    for r in rows:
        findings_list.append({
            "finding_id": r[0],
            "owasp_category": r[1],
            "status": r[2],
            "severity": r[3],
            "remediation": r[4],
            "evidence_hash": r[5],
        })

    baseline = ContinuousRegressionEngine.create_baseline(
        target_id=request.target_id,
        scan_id=request.scan_id,
        risk_score=scan_row[1] or 0,
        risk_grade=scan_row[2] or "N/A",
        findings_list=findings_list,
    )
    _target_baselines[request.target_id] = baseline
    return baseline.model_dump()


@router.get("/baseline/{target_id}")
async def get_baseline(target_id: int):
    """Fetches the active security baseline for a target."""
    if target_id not in _target_baselines:
        raise HTTPException(status_code=404, detail="No baseline established for this target yet.")
    return _target_baselines[target_id].model_dump()


@router.post("/diff")
async def compare_scan_with_baseline(request: DiffRequest, db: aiosqlite.Connection = Depends(get_db)):
    """Compares the current scan against the target's baseline to detect fixed vs new vulnerabilities."""
    baseline = _target_baselines.get(request.target_id)
    if not baseline:
        # If no explicit baseline set in cache, search for earliest completed scan for target
        cursor = await db.execute("SELECT id, overall_score, risk_grade FROM scan_runs WHERE target_id = ? AND status = 'COMPLETED' AND id != ? ORDER BY id ASC LIMIT 1", (request.target_id, request.current_scan_id))
        earliest = await cursor.fetchone()
        if not earliest:
            raise HTTPException(status_code=400, detail="Cannot perform regression diff: No baseline or prior scan found.")
        
        f_cursor = await db.execute("SELECT finding_id, owasp_category, status, severity, remediation, evidence_hash FROM findings WHERE scan_id = ?", (earliest[0],))
        f_rows = await f_cursor.fetchall()
        baseline = ContinuousRegressionEngine.create_baseline(
            target_id=request.target_id,
            scan_id=earliest[0],
            risk_score=earliest[1] or 0,
            risk_grade=earliest[2] or "N/A",
            findings_list=[{"finding_id": r[0], "owasp_category": r[1], "status": r[2], "severity": r[3], "remediation": r[4], "evidence_hash": r[5]} for r in f_rows]
        )
        _target_baselines[request.target_id] = baseline

    # Fetch current scan details
    curr_cursor = await db.execute("SELECT overall_score, risk_grade FROM scan_runs WHERE id = ?", (request.current_scan_id,))
    curr_scan = await curr_cursor.fetchone()
    if not curr_scan:
        raise HTTPException(status_code=404, detail="Current scan run not found")

    curr_findings_cursor = await db.execute("SELECT finding_id, owasp_category, status, severity, remediation, evidence_hash FROM findings WHERE scan_id = ?", (request.current_scan_id,))
    curr_rows = await curr_findings_cursor.fetchall()
    curr_findings = [{"finding_id": r[0], "owasp_category": r[1], "status": r[2], "severity": r[3], "remediation": r[4], "evidence_hash": r[5]} for r in curr_rows]

    comparison = ContinuousRegressionEngine.compare_against_baseline(
        baseline=baseline,
        current_scan_id=request.current_scan_id,
        current_score=curr_scan[0] or 0,
        current_grade=curr_scan[1] or "N/A",
        current_findings=curr_findings,
        gate_policy=request.gate_policy,
    )
    return comparison.model_dump()
