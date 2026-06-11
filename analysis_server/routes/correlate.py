import json

from pydantic import BaseModel

from services.processs import process_collection
from fastapi import APIRouter, HTTPException, Header, Request
from typing import Optional
from services import validator
from services.storage import CollectionStorage
from detection.correlator import Correlator
from detection.fusion import fuse_findings
router = APIRouter()

class CorrelateRequest(BaseModel):
    collection_id: str

@router.post("/api/correlate")
async def collect_data(
    request : CorrelateRequest
):
    try:
        storage = CollectionStorage.load(collection_id=request.collection_id)
    except Exception as e:
        raise HTTPException(status_code=404, detail="Collection not found")

    
    findings = storage.load_all_findings()
    events = storage.load_all_channels()

    fused = fuse_findings(findings)
    correlator = Correlator(events, fused)

    correlator.build_graph()
   # correlator.print_diagnostics()
    correlator._dev_export_html(f"collections/{request.collection_id}/graph.html")

    return {"status": "success", "collection_id": request.collection_id}
