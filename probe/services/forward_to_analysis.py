import httpx
from typing import Optional
from services.validator import compute_hash
from fastapi import HTTPException
from models.collection import CollectionSummary
import logging

logger = logging.getLogger(__name__)

CHUNK_SIZE = 10 * 1024 * 1024  

async def forward_to_analysis_server(
    payload: bytes,
    analysis_server_url: str,
    token: str = None,
    summary: Optional[CollectionSummary] = None,
) -> dict:
    if not token:
        raise HTTPException(status_code=500, detail="Missing probe token in config")

    collection_hash = compute_hash(payload)
    base_headers = {
        "X-Probe-Token": token,
    }
    if summary is not None:
        base_headers["X-Collection-Summary"] = summary.model_dump_json()

    total_chunks = -(-len(payload) // CHUNK_SIZE)   

    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:

        try:
            resp = await client.post(
                f"{analysis_server_url}/api/probe/ingest/start",
                headers=base_headers,
            )
            resp.raise_for_status()
            upload_id = resp.json()["upload_id"]
        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"Failed to start upload session: {e}")
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)

        for i in range(total_chunks):
            offset = i * CHUNK_SIZE
            chunk = payload[offset: offset + CHUNK_SIZE]
            chunk_headers = base_headers | {
                "Content-Type": "application/octet-stream",
                "X-Chunk-Index": str(i),
            }
            try:
                resp = await client.post(
                    f"{analysis_server_url}/api/probe/ingest/chunk/{upload_id}",
                    content=chunk,
                    headers=chunk_headers,
                    timeout=httpx.Timeout(120.0),
                )
                resp.raise_for_status()
            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                try:
                    await client.post(
                        f"{analysis_server_url}/api/probe/ingest/abort/{upload_id}",
                        headers=base_headers,
                        timeout=10.0,
                    )
                    logger.info(f"Aborted upload session {upload_id} after chunk {i} failure")
                except Exception:
                    pass
                detail = str(e) if isinstance(e, httpx.RequestError) else f"{e.response.status_code} {e.response.text}"
                logger.error(f"Failed on chunk {i}: {detail}")
                raise HTTPException(status_code=500, detail=f"Chunk {i} upload failed: {detail}")

        complete_headers = base_headers | {
            "X-Collection-Hash": collection_hash,
        }
        try:
            resp = await client.post(
                f"{analysis_server_url}/api/probe/ingest/complete/{upload_id}",
                headers=complete_headers,
                timeout=httpx.Timeout(300.0),
            )
            resp.raise_for_status()
            result = resp.json()
            logger.info(f"Forward complete: {result}")
            return result
        except httpx.RequestError as e:
            logger.error(f"Failed to complete upload session: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to complete upload: {e}")
        except httpx.HTTPStatusError as e:
            logger.error(f"Server rejected complete: {e.response.status_code} {e.response.text}")
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
