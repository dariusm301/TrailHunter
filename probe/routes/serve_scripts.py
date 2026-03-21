from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from config import COLLECTOR_DIR

router = APIRouter()

@router.get("/{platform}/{filename}")
async def server_module(platform: str, filename: str):
    if "collector" in filename:
        script_path = COLLECTOR_DIR / filename
    else:
        script_path = COLLECTOR_DIR / "modules" / platform / filename

    if not script_path.exists():
        raise HTTPException(status_code=404, detail="Script not found")
    
    return PlainTextResponse(script_path.read_text())
    