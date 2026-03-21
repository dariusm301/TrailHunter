from fastapi import APIRouter, Header, HTTPException, Request
from typing import Optional
from models import CollectionPayload, CollectResponse
from services import validator, storage
from config import settings

router = APIRouter()

@router.post("/collect", response_model=CollectResponse)
async def collect_data(
    request: Request,
    x_collection_hash: Optional[str] = Header(None)
):
    if not x_collection_hash:
        raise HTTPException(status_code=400, detail="Missing X-Collection-Hash header")
    
    raw_body = await request.body()

    if not validator.verify_hash(raw_body, x_collection_hash):
        raise HTTPException(status_code=400, detail="Hash mismatch - data integrity check failed")
    
    payload = CollectionPayload.model_validate_json(raw_body)

    if settings.store_local:
        await storage.save(payload)


    return CollectResponse(
        status="ok",
        hostname=payload.metadata.hostname,
        collected_at=payload.metadata.collected_at
    )
    