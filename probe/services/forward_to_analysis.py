import json
import httpx
from services.validator import compute_hash
from fastapi import HTTPException
from models.collection import CollectionSummary

async def forward_to_analysis_server(payload: bytes, analysis_server_url: str, hash: str = None, summary: CollectionSummary = None) -> str | dict:
    if hash is None:
        hash = compute_hash(payload)
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(f"{analysis_server_url}/api/ingest", content=payload, 
                                         headers={"Content-Type": "application/octet-stream",
                                                  "X-Collection-Hash": f"{hash}",
                                                  "X-Collection-Summary": f"{summary.model_dump_json()}"}
                                         )
            response.raise_for_status()
            return json.loads(response.text)
    except httpx.RequestError as exc:
        print(f"An error occurred while requesting {exc.request.url!r}.")
        raise HTTPException(status_code=500, detail=str(exc))
    except httpx.HTTPStatusError as exc:
        print(f"Error response {exc.response.status_code} while requesting {exc.request.url!r}.")
        raise HTTPException(status_code=exc.response.status_code, detail=str(exc))