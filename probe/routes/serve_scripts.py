from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from config import COLLECTOR_DIR
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

@router.get("/{platform}/{filename}")
async def serve_module(platform: str, filename: str):
    base = COLLECTOR_DIR
    if "collector" in filename:
        script_path = base / filename
    else:
        script_path = base / "modules" / platform / filename

    if not script_path.exists():
        raise HTTPException(status_code=404, detail="Script not found")
    script_path = script_path.resolve()
    
    return PlainTextResponse(script_path.read_text())
    
