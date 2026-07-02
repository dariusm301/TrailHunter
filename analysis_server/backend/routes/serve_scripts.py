from services.database import get_db
from services.dependencies import get_current_probe, get_current_user
from models.auth import ProbeToken, User
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import PlainTextResponse
from config import COLLECTOR_DIR
from pathlib import Path
from sqlalchemy.orm import Session

router = APIRouter()

@router.get("/{platform}/{filename}")
async def serve_module(platform: str, 
                       filename: str, 
                       probe: ProbeToken = Depends(get_current_probe),
                       db_session :Session = Depends(get_db)
                       ):
    base = COLLECTOR_DIR
    if "collector" in filename:
        script_path = base / filename
    else:
        script_path = base / "modules" / platform / filename
        
    if not script_path.is_relative_to(base):
        raise HTTPException(status_code=404, detail="Script not found")
    if not script_path.exists() or script_path.suffix != ".ps1":
        raise HTTPException(status_code=404, detail="Script not found")
    script_path = script_path.resolve()
    
    return PlainTextResponse(script_path.read_text(encoding="utf-8-sig").replace("\r\n", "\n"))
    