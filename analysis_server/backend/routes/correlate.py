from services.dependencies import get_current_user
from models.auth import User
from services.database import get_db
from fastapi import APIRouter, HTTPException, Response, Depends
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session

from services.storage import CollectionStorage
from services.correlation_jobs import start_correlation, get_job

router = APIRouter()


class CorrelateRequest(BaseModel):
    collection_id: str
    force: Optional[bool] = False   


@router.post("/api/correlate")
async def correlate(request: CorrelateRequest, 
                    response: Response, 
                    current_user : User = Depends(get_current_user), 
                    db_session: Session = Depends(get_db)):
    try:
        CollectionStorage.load(collection_id=request.collection_id, user_id=current_user.id, db_session=db_session)
    except Exception:
        raise HTTPException(status_code=404, detail="Collection not found")

    job = await start_correlation(request.collection_id, force=bool(request.force), user_id=current_user.id, db_session=db_session)
    if job.status == "running":
        response.status_code = 202
    return job.envelope()


@router.get("/api/correlate/{collection_id:path}/status")
async def correlate_status(collection_id: str, 
                           current_user : User = Depends(get_current_user), 
                           db_session: Session = Depends(get_db)):
    job = get_job(collection_id)
    if job is not None:
        return job.envelope()

    try:
        cached = CollectionStorage.load(collection_id=collection_id, user_id=current_user.id, db_session=db_session).load_correlated()
    except Exception:
        cached = None
    if cached is not None:
        return {"status": "done", "phase": "cached", "graph": cached,
                "progress": None, "error": None, "elapsed": 0}

    return {"status": "idle", "phase": "not_correlated", "graph": None,
            "progress": None, "error": None, "elapsed": 0}