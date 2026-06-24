from datetime import datetime, timezone
import json
from models.auth import ProbeToken
from fastapi import APIRouter, HTTPException, Header, Request, Depends
from sqlalchemy.orm import Session
from typing import Optional

from services.database import get_db
from services.dependencies import get_current_probe
from services.ingest import handle_ingest

router = APIRouter()

@router.post("/api/probe/ingest")
async def collect_data_probe(
    request: Request,
    x_collection_hash: Optional[str] = Header(None),
    x_collection_summary: Optional[str] = Header(None),
    probe: ProbeToken = Depends(get_current_probe),
    db_session: Session = Depends(get_db),
):
    if not x_collection_hash:
        raise HTTPException(status_code=400, detail="Missing X-Collection-Hash header")
    raw_body = await request.body()
    payload = json.loads(raw_body.decode("utf-8"))
    collection_storage = handle_ingest(
        hostname=payload["metadata"]["hostname"],
        user_id=probe.user_id,
        raw_body=raw_body,
        x_collection_hash=x_collection_hash,
        x_collection_summary=x_collection_summary,
        db_session=db_session,
    )

    if probe.single_use:
        probe.used_at = datetime.now(timezone.utc)
        db_session.commit()

    return {"status": "accepted", "hash": x_collection_hash, "collection_id": collection_storage.collection_id}