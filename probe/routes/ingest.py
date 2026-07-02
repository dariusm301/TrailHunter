from fastapi import APIRouter, Header, HTTPException, Request
from typing import Optional
from models import CollectionPayload, CollectResponse
from models.collection import CollectionSummary
from services import validator, storage
from services.verify_connection import verify_internet_connection
from services.forward_to_analysis import forward_to_analysis_server
from services.ip_collector import get_collector_ips
from config import probe_config
import hashlib
import json
import os
import shutil
from pathlib import Path
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

CHUNKS_DIR = Path(__file__).parent.parent / "data" / "chunks"
CHUNKS_DIR.mkdir(parents=True, exist_ok=True)

UPLOAD_TTL_SECONDS = 3600  # sesiunile incomplete expiră după 1 oră


def _upload_dir(upload_id: str) -> Path:
    if not upload_id.isalnum():
        raise HTTPException(status_code=400, detail="Invalid upload_id")
    return CHUNKS_DIR / upload_id


async def _process_payload(raw_body: bytes, x_collection_hash: str) -> CollectResponse:
    """Validează, salvează local și forwardează payload-ul asamblat."""
    if not validator.verify_hash(raw_body, x_collection_hash):
        raise HTTPException(status_code=400, detail="Hash mismatch - data integrity check failed")

    payload = CollectionPayload.model_validate_json(raw_body)
    summary = CollectionSummary(
        collector_ip=get_collector_ips(),
        sha256=x_collection_hash,
    )

    try:
        if probe_config.get().get("local_storage"):
            await storage.save(raw_body, payload.metadata, summary)
    except Exception as e:
        logger.error(f"Failed to save data locally: {e}", exc_info=True)

    forwarded = False
    forward_error = None
    try:
        analysis_server_url = probe_config.get().get("analysis_server_url")
        token = probe_config.get().get("token")
        if analysis_server_url and token:
            if verify_internet_connection().get("status") == "ok":
                forward_response = await forward_to_analysis_server(
                    payload=raw_body,
                    analysis_server_url=analysis_server_url,
                    token=token,
                    summary=summary,
                )
                if forward_response.get("status") != "accepted":
                    logger.warning(f"Failed to forward: {forward_response.get('detail')}")
                    forward_error = forward_response.get("detail", "rejected by the server")
                else:
                    logger.info("Data successfully forwarded to analysis server")
                    forwarded = True
            else:
                logger.warning("No internet connection, skipping forward")
                forward_error = "no internet connection"
        else:
            forward_error = "analysis server url or token not configured"
            logger.warning(f"Missing config (url={bool(analysis_server_url)}, token={bool(token)})")
    except Exception as e:
        logger.error(f"Unexpected error during forward: {e}", exc_info=True)
        forward_error = str(e)

    probe_config.update(armed=False)

    return CollectResponse(
        status="ok",
        hostname=payload.metadata.hostname,
        collected_at=payload.metadata.collected_at,
        forwarded_to_analysis_server=forwarded,
        forward_error=forward_error,
    )


# ---------------------------------------------------------------------------
# Single-shot ingest (payload mic, backward compatible)
# ---------------------------------------------------------------------------

@router.post("/api/probe/ingest", response_model=CollectResponse)
async def ingest_data(
    request: Request,
    x_collection_hash: Optional[str] = Header(None),
):
    if not x_collection_hash:
        raise HTTPException(status_code=400, detail="Missing X-Collection-Hash header")
    raw_body = await request.body()
    return await _process_payload(raw_body, x_collection_hash)


# ---------------------------------------------------------------------------
# Chunked ingest
# ---------------------------------------------------------------------------

@router.post("/api/probe/ingest/start")
async def ingest_start():
    upload_id = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    upload_dir = _upload_dir(upload_id)
    upload_dir.mkdir()
    (upload_dir / "meta.json").write_text(json.dumps({
        "created_at": __import__("time").time()
    }))
    logger.info(f"Started upload session {upload_id}")
    return {"upload_id": upload_id}


@router.post("/api/probe/ingest/chunk/{upload_id}")
async def ingest_chunk(
    upload_id: str,
    request: Request,
    x_chunk_index: int = Header(...),
):
    upload_dir = _upload_dir(upload_id)
    if not upload_dir.exists():
        raise HTTPException(status_code=404, detail="Upload session not found")

    # TTL check
    meta = json.loads((upload_dir / "meta.json").read_text())
    if __import__("time").time() - meta["created_at"] > UPLOAD_TTL_SECONDS:
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise HTTPException(status_code=410, detail="Upload session expired")

    chunk_path = upload_dir / f"chunk_{x_chunk_index:06d}"
    with chunk_path.open("wb") as f:
        async for data in request.stream():
            f.write(data)

    logger.debug(f"Received chunk {x_chunk_index} for session {upload_id}")
    return {"chunk": x_chunk_index, "status": "ok"}


@router.post("/api/probe/ingest/complete/{upload_id}", response_model=CollectResponse)
async def ingest_complete(
    upload_id: str,
    x_collection_hash: str = Header(...),
):
    upload_dir = _upload_dir(upload_id)
    if not upload_dir.exists():
        raise HTTPException(status_code=404, detail="Upload session not found")

    chunks = sorted(
        upload_dir.glob("chunk_*"),
        key=lambda p: int(p.name.split("_")[1]),
    )
    if not chunks:
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail="No chunks found")

    # Verifică că nu lipsesc chunk-uri (gap detection)
    indices = [int(p.name.split("_")[1]) for p in chunks]
    expected = list(range(len(indices)))
    if indices != expected:
        missing = set(expected) - set(indices)
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"Missing chunks: {sorted(missing)}")

    # Asamblare
    assembled_path = upload_dir / "assembled"
    try:
        with assembled_path.open("wb") as out:
            for chunk_path in chunks:
                out.write(chunk_path.read_bytes())
        raw_body = assembled_path.read_bytes()
    except Exception as e:
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Assembly failed: {e}")

    # Cleanup chunks înainte de procesare (eliberează spațiu pe RPi)
    for chunk_path in chunks:
        chunk_path.unlink()

    try:
        result = await _process_payload(raw_body, x_collection_hash)
    finally:
        shutil.rmtree(upload_dir, ignore_errors=True)

    return result


@router.post("/api/probe/ingest/abort/{upload_id}")
async def ingest_abort(upload_id: str):
    upload_dir = _upload_dir(upload_id)
    if upload_dir.exists():
        shutil.rmtree(upload_dir, ignore_errors=True)
        logger.info(f"Aborted upload session {upload_id}")
    return {"status": "aborted", "upload_id": upload_id}
