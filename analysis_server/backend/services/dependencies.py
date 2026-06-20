from datetime import datetime, timedelta
from email.header import Header
import hashlib
import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session

from services.database import get_db
from models.auth import ProbeToken, User
from services.security import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        raise credentials_exception

    return user


def get_optional_current_user(
    token: str | None = Depends(oauth2_scheme_optional),
    db: Session = Depends(get_db),
) -> User | None:
    if token is None:
        return None
    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
    except JWTError:
        return None
    if user_id is None:
        return None
    return db.query(User).filter(User.id == user_id).first()

def generate_probe_token(db: Session, user_id: str, name: str, device_identifier: str | None = None,
                         expires_in_days: int | None = 30) -> tuple[str, ProbeToken]:
    
    raw_token = secrets.token_urlsafe(48)
    token_record = ProbeToken(
        user_id=user_id,
        name=name,
        device_identifier=device_identifier,
        token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
        expires_at=datetime.utcnow() + timedelta(days=expires_in_days) if expires_in_days is not None else None
    )
    db.add(token_record)
    db.commit()
    db.refresh(token_record)
    return raw_token, token_record

def verify_probe_token(db: Session, raw_token: str) -> ProbeToken | None:
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    token_record = db.query(ProbeToken).filter(
        ProbeToken.token_hash == token_hash,
        ProbeToken.revoked == False, 
    ).first()
    if token_record is None:
        return None
    if token_record.expires_at is not None and token_record.expires_at < datetime.utcnow():
        return None
    token_record.last_used_at = datetime.utcnow()
    db.commit()
    return token_record

def get_current_probe(
    x_probe_token: str = Header("X-Probe-Token"),
    db: Session = Depends(get_db),
) -> ProbeToken:
    token_record = verify_probe_token(db, x_probe_token)
    if token_record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked probe token",
        )
    return token_record