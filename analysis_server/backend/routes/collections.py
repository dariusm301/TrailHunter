from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from services.storage import CollectionStorage
from services.database import get_db
from services.dependencies import get_current_user 
from models.auth import User  
router = APIRouter()


class CollectionRequest(BaseModel):
    collection_id: str


@router.get("/api/collections")
async def get_all_collections(
    current_user: User = Depends(get_current_user),
    db_session=Depends(get_db),
):
    collection_ids = CollectionStorage.list_collections(current_user.id, db_session)
    scans = []

    for cid in collection_ids:
        try:
            storage = CollectionStorage.load(cid, current_user.id, db_session)
            summary = storage.load_summary()
            total_events = sum(count for count in summary.get("event_counts", {}).values())
            total_findings = sum(count for count in summary.get("finding_counts", {}).values())
            scan_data = {
                "id": cid,
                "host": storage.hostname,
                "collected_at": summary.get("collected_at", None),
                "event_count": total_events,
                "finding_count": total_findings,
                "actor_count": summary.get("actor_count", None),
                "max_severity": summary.get("max_severity", None),
                "has_collector": summary.get("probe", False),
            }
            scans.append(scan_data)
        except Exception as e:
            print(f"Skipping corrupt collection {cid}: {e}")
            continue

    return scans


@router.post("/api/delete")
async def delete_collection(
    request: CollectionRequest,
    current_user: User = Depends(get_current_user),
    db_session=Depends(get_db),
):
    try:
        collection = CollectionStorage.load(request.collection_id, current_user.id, db_session)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Collection not found")

    collection.delete()
    return {"message": f"Collection {request.collection_id} deleted successfully."}


@router.get("/api/collections/{collection_id:path}/findings")
async def get_findings_for_collection(
    collection_id: str,
    current_user: User = Depends(get_current_user),
    db_session=Depends(get_db),
):
    try:
        collection = CollectionStorage.load(collection_id, current_user.id, db_session)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Collection not found")

    reports = collection.load_all_reports()
    all_findings = []
    for report in reports:
        all_findings.extend(report.findings)

    if not all_findings:
        return {"status": "completed", "total_findings": 0, "max_severity": "info", "findings": []}

    order = ["critical", "high", "medium", "low", "info"]
    severities = {f.severity.value for f in all_findings}
    max_sev = next((s for s in order if s in severities), "info")

    return {
        "status": "completed",
        "total_findings": len(all_findings),
        "max_severity": max_sev,
        "findings": [f.model_dump() for f in all_findings],
    }

@router.get("/api/collections/{collection_id:path}/summary")
async def get_collection_summary(
    collection_id: str,
    current_user: User = Depends(get_current_user),
    db_session=Depends(get_db),
):
    try:
        collection = CollectionStorage.load(collection_id, current_user.id, db_session)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Collection not found")
    
    summary = collection.load_summary()
    if not summary:
        raise HTTPException(status_code=404, detail="Summary not found")
    
    return summary