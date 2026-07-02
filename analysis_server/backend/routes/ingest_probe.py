import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request, Depends
from sqlalchemy.orm import Session

from models.auth import ProbeToken
from services.database import get_db
from services.dependencies import get_current_probe
from services.ingest import handle_ingest
from services.ip_collector import get_collector_ips

router = APIRouter()

CHUNKS_DIR = Path(__file__).parent.parent / "data" / "trailhunter_chunks"
CHUNKS_DIR.mkdir(exist_ok=True)



def _upload_dir(upload_id: str) -> Path:
    if not upload_id.isalnum():
        raise HTTPException(status_code=400, detail="Invalid upload_id")
    return CHUNKS_DIR / upload_id


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
    collection_storage = handle_ingest(
        hostname=json.loads(raw_body)["metadata"]["hostname"],
        user_id=probe.user_id,
        raw_body=raw_body,
        x_collection_hash=x_collection_hash,
        x_collection_summary=x_collection_summary,
        db_session=db_session,
    )

    if probe.single_use:
        probe.used_at = datetime.now(timezone.utc)
        db_session.commit()

    return {
        "status": "accepted",
        "hash": x_collection_hash,
        "collection_id": collection_storage.collection_id,
        "forwarded_to_analysis_server": True,
    }

@router.post("/api/probe/ingest/start")
async def ingest_start(probe: ProbeToken = Depends(get_current_probe)):
    upload_id = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    upload_dir = _upload_dir(upload_id)
    upload_dir.mkdir()
    (upload_dir / "meta.json").write_text(json.dumps({
        "user_id": probe.user_id,
        "token_id": probe.id,
        "token_hash": probe.token_hash
    }))
    return {"upload_id": upload_id}

@router.post("/api/probe/ingest/chunk/{upload_id}")
async def ingest_chunk(
    upload_id: str,
    request: Request,
    x_chunk_index: int = Header(...),
    x_probe_token: str = Header(...),
):
    upload_dir = _upload_dir(upload_id)
    if not upload_dir.exists():
        raise HTTPException(status_code=404, detail="Upload session not found")

    meta = json.loads((upload_dir / "meta.json").read_text())
    if hashlib.sha256(x_probe_token.encode()).hexdigest() != meta["token_hash"]:
        raise HTTPException(status_code=401, detail="Token mismatch")

    chunk_path = upload_dir / f"chunk_{x_chunk_index:06d}"
    with chunk_path.open("wb") as f:
        async for data in request.stream():
            f.write(data)
    return {"chunk": x_chunk_index}


@router.post("/api/probe/ingest/complete/{upload_id}")
async def ingest_complete(
    request: Request,
    upload_id: str,
    x_collection_hash: str = Header(...),
    x_collection_summary: Optional[str] = Header(None),
    probe: ProbeToken = Depends(get_current_probe),
    db_session: Session = Depends(get_db),
):
    upload_dir = _upload_dir(upload_id)
    if not upload_dir.exists():
        raise HTTPException(status_code=404, detail="Upload session not found")

    chunks = sorted(
        upload_dir.glob("chunk_*"),
        key=lambda p: int(p.name.split("_")[1]),
    )

    if not chunks:
        raise HTTPException(status_code=400, detail="No chunks found")

    assembled_path = upload_dir / "assembled"
    with assembled_path.open("wb") as out:
        for chunk_path in chunks:
            out.write(chunk_path.read_bytes())

    raw_body = assembled_path.read_bytes()

    for chunk_path in chunks:
        chunk_path.unlink()

    collector_ips = get_collector_ips()
    try:
        collection_storage = handle_ingest(
            hostname=json.loads(raw_body)["metadata"]["hostname"],
            user_id=probe.user_id,
            raw_body=raw_body,
            x_collection_hash=x_collection_hash,
            x_collection_summary=x_collection_summary,
            db_session=db_session,
            collector_ip=collector_ips,
            token_id=probe.id
        )
    finally:
        shutil.rmtree(upload_dir, ignore_errors=True)

    probe.last_used_at = datetime.now(timezone.utc)
    if probe.single_use:
        probe.used_at = datetime.now(timezone.utc)
    db_session.commit() 

    return {
        "status": "accepted",
        "hash": x_collection_hash,
        "collection_id": collection_storage.collection_id,
        "forwarded_to_analysis_server": True,
    }