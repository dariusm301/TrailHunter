import httpx
from services.validator import compute_hash
async def forward_to_analysis_server(payload: bytes, analysis_server_url: str, hash: str = None) -> dict:
    if hash is None:
        return "Hash is required for forwarding to analysis server."
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(f"{analysis_server_url}", content=payload, 
                                         headers={"Content-Type": "application/octet-stream",
                                                  "X-Collection-Hash": f"{hash}"}
                                         )
            response.raise_for_status()
            return {"status": "success", "detail": response.text}
    except httpx.RequestError as exc:
        print(f"An error occurred while requesting {exc.request.url!r}.")
        return {"status": "error", "detail": str(exc)}
    except httpx.HTTPStatusError as exc:
        print(f"Error response {exc.response.status_code} while requesting {exc.request.url!r}.")
        return {"status": "error", "detail": str(exc)}