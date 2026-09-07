from fastapi import APIRouter, Depends, HTTPException
import json
import aiosqlite
import httpx
from pydantic import BaseModel, HttpUrl
from app.db.session import get_db
from app.schemas.target import TargetContract, TargetResponse

router = APIRouter(prefix="/targets", tags=["Targets"])

DEFAULT_TARGET = {
    "name": "Meridian Support AI (Reference Target)",
    "base_url": "http://127.0.0.1:8000/target-app",
    "model_name": "qwen-flash",
    "target_type": "EXTERNAL_SUPPORT",
    "target_mode": "INSTRUMENTED",
    "capabilities": {
        "chat": True,
        "rag": False,
        "tools": False,
        "data_access": False,
        "tool_names": []
    }
}

class ConnectionCheckRequest(BaseModel):
    base_url: str

@router.post("/test-connection")
async def test_connection(request: ConnectionCheckRequest):
    """Validate a target by reading its real health and contract endpoints."""
    base_url = request.base_url.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            health = await client.get(f"{base_url}/health")
            contract = await client.get(f"{base_url}/contract")
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail=f"Connection failed: {exc}") from exc

    if health.status_code != 200 or contract.status_code != 200:
        raise HTTPException(
            status_code=422,
            detail={"message": "Target did not expose a valid health/contract interface.", "health_status": health.status_code, "contract_status": contract.status_code},
        )
    try:
        return {"connected": True, "health": health.json(), "contract": contract.json()}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Target returned a non-JSON health or contract response.") from exc

@router.post("", response_model=TargetResponse)
async def create_target(target: TargetContract, db: aiosqlite.Connection = Depends(get_db)):
    cursor = await db.execute(
        "INSERT INTO targets (name, base_url, model_name, target_type, target_mode, capabilities_json) VALUES (?, ?, ?, ?, ?, ?)",
        (target.name, target.base_url, target.model_name, target.target_type, target.target_mode, json.dumps(target.capabilities.model_dump()))
    )
    await db.commit()
    target_id = cursor.lastrowid
    return TargetResponse(
        id=target_id,
        name=target.name,
        base_url=target.base_url,
        model_name=target.model_name,
        target_type=target.target_type,
        target_mode=target.target_mode,
        capabilities=target.capabilities
    )

@router.get("", response_model=list[TargetResponse])
async def list_targets(db: aiosqlite.Connection = Depends(get_db)):
    cursor = await db.execute("SELECT id, name, base_url, model_name, target_type, target_mode, capabilities_json FROM targets ORDER BY id DESC")
    rows = await cursor.fetchall()
    results = []
    for r in rows:
        results.append(TargetResponse(
            id=r[0],
            name=r[1],
            base_url=r[2],
            model_name=r[3],
            target_type=r[4],
            target_mode=r[5],
            capabilities=json.loads(r[6])
        ))
    return results


@router.get("/{target_id}/documents")
async def get_target_documents(target_id: int, db: aiosqlite.Connection = Depends(get_db)):
    cursor = await db.execute("SELECT id, name, base_url, target_type, capabilities_json FROM targets WHERE id = ?", (target_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Target not found")
    
    base_url = row[2]
    target_type = row[3]
    
    if target_type == "INTERNAL_RAG" or "internal-rag" in base_url:
        from app.internal_rag.rag_store import internal_vector_store
        catalog = internal_vector_store.get_catalog()
        return {
            "target_id": target_id,
            "target_name": row[1],
            "has_rag": True,
            "document_count": len(catalog),
            "documents": catalog
        }
    
    return {
        "target_id": target_id,
        "target_name": row[1],
        "has_rag": False,
        "document_count": 0,
        "documents": []
    }
