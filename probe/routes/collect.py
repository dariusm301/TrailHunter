from fastapi import APIRouter, Header, HTTPException, Request
from typing import Optional
from models import CollectionPayload, CollectResponse
from services import validator, storage
from config import settings
from services.verify_connection import verify_internet_connection, verify_analysis_server_connection
from services.forward_to_analysis import forward_to_analysis_server

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

    try:
        if settings.store_local:
            await storage.save(payload)
    except Exception as e:
        print(f"Failed to save data locally: {e}")

    try:
        if verify_internet_connection():
            if verify_analysis_server_connection(settings.analysis_server_url):
                    forward_response = await forward_to_analysis_server(payload.model_dump(), settings.analysis_server_url)
                    if forward_response.get("status") != "ok":
                        print(f"Failed to forward data to analysis server: {forward_response.get('detail')}")
                    else:
                        print("Data successfully forwarded to analysis server")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return CollectResponse(
        status="ok",
        hostname=payload.metadata.hostname,
        collected_at=payload.metadata.collected_at
    )
    