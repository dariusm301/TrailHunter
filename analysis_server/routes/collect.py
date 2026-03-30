from fastapi import APIRouter, HTTPException, Header, Request
from typing import Optional
from services import validator, ingestor

router = APIRouter()

@router.post("/collect")
async def collect_data(
    request : Request,
    x_collection_hash: Optional[str] = Header(None)
):
    if not x_collection_hash:
        raise HTTPException(status_code=400, detail="Missing X-Collection-Hash header")
    
    raw_body = await request.body()

    if not validator.verify_hash(raw_body, x_collection_hash):
        raise HTTPException(status_code=400, detail="Hash mismatch - data integrity check failed")
    ingestor.prepare(raw_body, x_collection_hash)
    return 0