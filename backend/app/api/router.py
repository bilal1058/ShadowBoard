from fastapi import APIRouter
from app.api.endpoints import targets, policies, scans, findings

api_router = APIRouter(prefix="/api")
api_router.include_router(targets.router)
api_router.include_router(policies.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
