from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from services.database import get_db
from services.dependencies import get_current_user
from services.dependencies import generate_probe_token
from models.auth import User, ProbeToken

router = APIRouter()


class ProbeTokenCreateRequest(BaseModel):
    name: str
    device_identifier: Optional[str] = None
    expires_in_days: Optional[int] = 30  


class ProbeTokenCreateResponse(BaseModel):
    id: str
    name: str
    token: str 
    expires_at: Optional[datetime]


class ProbeTokenOut(BaseModel):
    id: str
    name: str
    device_identifier: Optional[str]
    created_at: datetime
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    revoked: bool

    class Config:
        from_attributes = True


@router.post("/api/probes/tokens", response_model=ProbeTokenCreateResponse)
async def create_probe_token(
    request: ProbeTokenCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    raw_token, record = generate_probe_token(
        db=db,
        user_id=current_user.id,
        name=request.name,
        device_identifier=request.device_identifier,
        expires_in_days=request.expires_in_days,
    )
    return ProbeTokenCreateResponse(
        id=record.id, name=record.name, token=raw_token, expires_at=record.expires_at,
    )


@router.get("/api/probes/tokens", response_model=list[ProbeTokenOut])
async def list_probe_tokens(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(ProbeToken)
        .filter(ProbeToken.user_id == current_user.id)
        .order_by(ProbeToken.created_at.desc())
        .all()
    )


@router.delete("/api/probes/tokens/{token_id}")
async def revoke_probe_token(
    token_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    record = (
        db.query(ProbeToken)
        .filter(ProbeToken.id == token_id, ProbeToken.user_id == current_user.id)
        .first()
    )
    if record is None:
        raise HTTPException(status_code=404, detail="Probe token not found")
    record.revoked = True
    db.commit()
    return {"message": "Token revoked"}