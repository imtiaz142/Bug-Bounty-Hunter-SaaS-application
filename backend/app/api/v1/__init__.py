from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.scans import router as scans_router
from app.api.v1.findings import router as findings_router
from app.api.v1.agents import router as agents_router
from app.api.v1.reports import router as reports_router
from app.api.v1.recon import router as recon_router
from app.api.v1.settings import router as settings_router

api_v1_router = APIRouter()

api_v1_router.include_router(auth_router, prefix="/auth", tags=["auth"])
api_v1_router.include_router(scans_router, prefix="/scans", tags=["scans"])
api_v1_router.include_router(findings_router, prefix="/scans/{scan_id}/findings", tags=["findings"])
api_v1_router.include_router(agents_router, prefix="/scans/{scan_id}/agents", tags=["agents"])
api_v1_router.include_router(reports_router, prefix="/scans/{scan_id}/report", tags=["reports"])
api_v1_router.include_router(recon_router, prefix="/scans/{scan_id}/recon", tags=["recon"])
api_v1_router.include_router(settings_router, prefix="/settings", tags=["settings"])
