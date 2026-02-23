"""Monitor router — Fase 2 (not yet implemented)."""

from fastapi import APIRouter, HTTPException

router = APIRouter()

NOT_IMPLEMENTED = {
    "error": "Monitor tier available in Fase 2",
    "code": "NOT_IMPLEMENTED",
}


@router.post("/v1/monitor/subscribe")
async def monitor_subscribe():
    raise HTTPException(status_code=501, detail=NOT_IMPLEMENTED)


@router.delete("/v1/monitor/{skill_id}")
async def monitor_unsubscribe(skill_id: str):
    raise HTTPException(status_code=501, detail=NOT_IMPLEMENTED)


@router.get("/v1/monitor/{skill_id}/history")
async def monitor_history(skill_id: str):
    raise HTTPException(status_code=501, detail=NOT_IMPLEMENTED)
