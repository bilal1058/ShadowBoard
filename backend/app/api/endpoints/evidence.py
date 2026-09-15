"""API Router for Verifiable Evidence System."""

from fastapi import APIRouter, HTTPException, Depends, Response
from pydantic import BaseModel
from typing import Dict, Any, List
import aiosqlite
import json

from app.db.session import get_db
from app.evidence import EvidenceBundler, StandaloneVerifier

router = APIRouter(prefix="/evidence", tags=["Verifiable Evidence"])


class VerifyEvidenceRequest(BaseModel):
    package_data: Dict[str, Any]


@router.get("/{finding_id}/package")
async def get_evidence_package(finding_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Generates and returns an independently verifiable cryptographic evidence package for a finding."""
    cursor = await db.execute(
        """
        SELECT f.scan_id, f.finding_id, f.owasp_category, f.status, f.severity, f.remediation, f.evidence_json, f.evidence_hash,
               s.target_id, t.name, t.target_mode
        FROM findings f
        JOIN scan_runs s ON f.scan_id = s.id
        JOIN targets t ON s.target_id = t.id
        WHERE f.finding_id = ?
        """,
        (finding_id,)
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    scan_id = row[0]
    finding_id = row[1]
    owasp_cat = row[2]
    status = row[3]
    severity = row[4]
    remediation = row[5]
    evidence_json = json.loads(row[6]) if isinstance(row[6], str) else row[6]
    target_id = row[8]
    target_name = row[9]
    target_mode = row[10]

    # Fetch attempts / execution events for this scan
    att_cursor = await db.execute(
        "SELECT prompt_text, response_text, strategy FROM attack_attempts WHERE scan_id = ? ORDER BY id ASC LIMIT 5",
        (scan_id,)
    )
    att_rows = await att_cursor.fetchall()
    prompts = [r[0] for r in att_rows] if att_rows else ["Audited attack sequence probe."]
    strategies = [r[2] for r in att_rows] if att_rows else ["adaptive_fsm"]
    last_response = att_rows[-1][1] if att_rows else "Audited target output."

    ev_cursor = await db.execute(
        "SELECT event_type, event_data FROM execution_events WHERE scan_id = ? ORDER BY id ASC LIMIT 10",
        (scan_id,)
    )
    ev_rows = await ev_cursor.fetchall()
    events = []
    for er in ev_rows:
        try:
            ev_data = json.loads(er[1]) if isinstance(er[1], str) else er[1]
        except Exception:
            ev_data = {}
        events.append({"event_type": er[0], "event_data": ev_data})

    pkg = EvidenceBundler.create_package(
        scan_id=scan_id,
        target_id=target_id,
        target_name=target_name,
        finding_id=finding_id,
        rule_id=finding_id,
        rule_name=f"Policy Assertion: {finding_id}",
        severity=severity,
        owasp_category=owasp_cat,
        attack_prompts=prompts,
        strategies_used=strategies,
        response_text=last_response,
        execution_events=events,
        violation_details=evidence_json,
        remediation_text=remediation,
        target_mode=target_mode,
    )

    return pkg.model_dump()


@router.post("/verify")
def verify_offline_package(request: VerifyEvidenceRequest):
    """Verifies the cryptographic integrity and authenticity of an evidence package."""
    valid, message, summary = StandaloneVerifier.verify_package(request.package_data)
    return {
        "verified": valid,
        "message": message,
        "summary": summary,
    }
