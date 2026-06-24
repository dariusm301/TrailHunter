import json
import httpx
from typing import Optional
from services.validator import compute_hash
from fastapi import HTTPException
from models.collection import CollectionSummary
import logging

logger = logging.getLogger(__name__)

async def forward_to_analysis_server(
    payload: bytes,
    analysis_server_url: str,
    token: str = None,
    summary: Optional[CollectionSummary] = None,
) -> dict:
    hash = compute_hash(payload)

    if not token:
        raise HTTPException(status_code=500, detail="Missing probe token in config")

    headers = {
        "Content-Type": "application/octet-stream",
        "X-Collection-Hash": hash,
        "X-Probe-Token": token,
    }
    if summary is not None:
        headers["X-Collection-Summary"] = summary.model_dump_json()

    try:
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                f"{analysis_server_url}/api/probe/ingest",
                content=payload,
                headers=headers,
            )
            response.raise_for_status()
            return response.json()
    except httpx.RequestError as exc:
        logger.error(f"An error occurred while requesting {exc.request.url!r}: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error response {exc.response.status_code} while requesting {exc.request.url!r}.")
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)
