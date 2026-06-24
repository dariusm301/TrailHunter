from fastapi import APIRouter, Header, HTTPException, Request
from typing import Optional
from models import CollectionPayload, CollectResponse
from models.collection import CollectionSummary
from services import validator, storage
from services.verify_connection import verify_internet_connection
from services.forward_to_analysis import forward_to_analysis_server
from services.ip_collector import get_collector_ips
import json
from config import probe_config
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/api/probe/ingest", response_model=CollectResponse)
async def ingest_data(
    request: Request,
    x_collection_hash: Optional[str] = Header(None)
):
    if not x_collection_hash:
        raise HTTPException(status_code=400, detail="Missing X-Collection-Hash header")
    
    raw_body = await request.body()

    if not validator.verify_hash(raw_body, x_collection_hash):
        raise HTTPException(status_code=400, detail="Hash mismatch - data integrity check failed")
    
    payload = CollectionPayload.model_validate_json(raw_body)
    summary = CollectionSummary(
        collector_ip=get_collector_ips(),
        sha256=x_collection_hash
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
                    forward_response = await forward_to_analysis_server(payload=raw_body,
                                                                        analysis_server_url=analysis_server_url,
                                                                        token = token,
                                                                        summary=summary)
                    if forward_response.get("status") != "accepted":
                        logger.warning(f"Failed to forward data to analysis server: {forward_response.get('detail')}")
                        forward_error = forward_response.get("detail", "rejected by the server")
                    else:
                        logger.info("Data successfully forwarded to analysis server")
                        forwarded = True
            else:
                logger.warning("Error: no internet")
        else:
            forward_error = "analysis server url or token not configured"
            logger.warning(f"Error: missing config (url={bool(analysis_server_url)}, token={bool(token)})")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        forward_error = str(e)

    probe_config.update(armed=False)
    return CollectResponse(
        status="ok",
        hostname=payload.metadata.hostname,
        collected_at=payload.metadata.collected_at,
        forwarded_to_analysis_server=forwarded,
        forward_error=forward_error
    )
    
