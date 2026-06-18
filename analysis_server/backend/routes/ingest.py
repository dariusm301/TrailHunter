import json

from models.events import CollectionSummary
from services import storage
from services.processs import process_collection
from fastapi import APIRouter, HTTPException, Header, Request
from typing import Optional
from services import validator
from services.storage import CollectionStorage

router = APIRouter()

@router.post("/api/ingest")
async def collect_data(
    request : Request,
    x_collection_hash: Optional[str] = Header(None),
    x_collection_summary: Optional[str] = Header(None)
):
    if not x_collection_hash:
        raise HTTPException(status_code=400, detail="Missing X-Collection-Hash header")
    
    raw_body = await request.body()

    if not validator.verify_hash(raw_body, x_collection_hash):
        raise HTTPException(status_code=400, detail="Hash mismatch - data integrity check failed")
    
    payload = json.loads(raw_body.decode("utf-8"))
    
    storage = CollectionStorage.create(payload['metadata']['hostname'])
    summary = CollectionSummary.model_validate_json(x_collection_summary) if x_collection_summary else None
    storage.save_summary(summary=summary.model_dump())
    
    if not storage.save_raw(raw_body, x_collection_hash):
        raise HTTPException(status_code=400, detail="Failed to save data - hash mismatch")
    
    
    process_collection(storage)

    return {"status": "accepted", "hash": x_collection_hash}