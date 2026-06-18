from fastapi import APIRouter
from services.storage import CollectionStorage
from pydantic import BaseModel
from fastapi.responses import JSONResponse

router = APIRouter()

class CollectionRequest(BaseModel):
    collection_id: str

@router.get("/api/collections")
async def get_all_collections():
    """
    """
    collection_ids = CollectionStorage.list_collections()
    scans = []
    
    for cid in collection_ids:
        try:
            storage = CollectionStorage.load(cid)
            summary = storage.load_summary()
            total_events = sum(count for count in summary.get("event_counts", {}).values())
            total_findings = sum(count for count in summary.get("finding_counts", {}).values())

            scan_data = {
                "id": cid,
                "host": storage.hostname,
                "collected_at": storage.timestamp,
                "event_count": total_events,
                "finding_count": total_findings,
                "actor_count": summary.get("actor_count", None),
                "max_severity": summary.get("max_severity", None),
                "has_collector": summary.get("probe", False)
            }
            
            
            scans.append(scan_data)
        except Exception as e:
            print(f"Skipping corrupt collection {cid}: {e}")
            continue
            
    return scans


@router.post("/api/delete")
async def delete_collection(request: CollectionRequest):
    """
    Delete a collection by its ID.
    """
    try:
        collection = CollectionStorage.load(request.collection_id)
        collection.delete()
        return {"message": f"Collection {request.collection_id} deleted successfully."}
    except Exception as e:
        print(f"Error occurred while deleting collection {request.collection_id}: {e}")
        return {"error": str(e)}
    

@router.get("/api/collections/{collection_id:path}/findings")
async def get_findings_for_collection(collection_id: str):
    try:
        collection = CollectionStorage.load(collection_id)
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
    except FileNotFoundError:
        return JSONResponse(status_code=404, content={"error": "Collection not found"})
    except Exception as e:
        return {"error": str(e)}