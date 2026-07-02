from datetime import datetime, timedelta, timezone
import hashlib
import secrets

from fastapi import Depends, HTTPException, status, Header
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

def generate_probe_token(
    db: Session,
    user_id: str,
    name: str,
    token_type: str = "hardware",
    device_identifier: str | None = None,
    expires_in: timedelta | None = timedelta(days=30),
    single_use: bool = False,
) -> tuple[str, ProbeToken]:
    raw_token = secrets.token_urlsafe(48)
    token_record = ProbeToken(
        user_id=user_id,
        name=name,
        token_type=token_type,
        device_identifier=device_identifier,
        token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
        expires_at=datetime.now(timezone.utc) + expires_in if expires_in is not None else None,
        single_use=single_use,
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
    if token_record.expires_at and token_record.expires_at < datetime.now(timezone.utc):
        return None
    if token_record.single_use and token_record.used_at is not None:
        return None
    return token_record

def get_current_probe(
    x_probe_token: str = Header(...),
    db: Session = Depends(get_db),
) -> ProbeToken:
    token_record = verify_probe_token(db, x_probe_token)
    if token_record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked probe token",
        )
    return token_record