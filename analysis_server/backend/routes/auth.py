from datetime import datetime, timedelta

from services.dependencies import get_current_user
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from config import settings
from services.database import get_db
from models.auth import RefreshToken, User
from services.security import (
    create_access_token,
    generate_refresh_token,
    hash_token,
    verify_password,
)


from pydantic import BaseModel

from services.dependencies import get_optional_current_user
from services.security import hash_password


router = APIRouter(prefix="/api/auth", tags=["auth"])


def _issue_refresh_token(db: Session, user_id: str) -> str:
    raw_token = generate_refresh_token()
    expires_at = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)

    db_token = RefreshToken(
        user_id=user_id,
        token_hash=hash_token(raw_token),
        expires_at=expires_at,
    )
    db.add(db_token)
    db.commit()
    return raw_token


def _set_refresh_cookie(response: Response, raw_token: str) -> None:
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=raw_token,
        httponly=True,
        secure=False,  
        samesite="strict",
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        path="/api/auth",  
    )


@router.get("/setup-required")
def setup_required(db: Session = Depends(get_db)):
    user_count = db.query(User).count()
    return {"setup_required": user_count == 0}


@router.post("/login")
def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")

    access_token = create_access_token(subject=user.id)
    raw_refresh_token = _issue_refresh_token(db, user.id)
    _set_refresh_cookie(response, raw_refresh_token)

    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/refresh")
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    raw_token = request.cookies.get(settings.refresh_cookie_name)
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token"
        )

    token_hash = hash_token(raw_token)
    db_token = (
        db.query(RefreshToken)
        .filter(RefreshToken.token_hash == token_hash, RefreshToken.revoked.is_(False))
        .first()
    )

    if not db_token or db_token.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    
    db_token.revoked = True
    db.add(db_token)
    db.commit()

    new_access_token = create_access_token(subject=db_token.user_id)
    new_raw_refresh_token = _issue_refresh_token(db, db_token.user_id)
    _set_refresh_cookie(response, new_raw_refresh_token)

    return {"access_token": new_access_token, "token_type": "bearer"}


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    raw_token = request.cookies.get(settings.refresh_cookie_name)
    if raw_token:
        token_hash = hash_token(raw_token)
        db_token = (
            db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
        )
        if db_token:
            db_token.revoked = True
            db.add(db_token)
            db.commit()

    response.delete_cookie(key=settings.refresh_cookie_name, path="/api/auth")
    return {"detail": "Logged out"}


class UserCreate(BaseModel):
    username: str
    password: str


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(
    payload: UserCreate,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
):
    user_count = db.query(User).count()

    if user_count > 0:
        if current_user is None or not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only an administrator can create new accounts",
            )

    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken",
        )

    new_user = User(
        username=payload.username,
        hashed_password=hash_password(payload.password),
        is_admin=(user_count == 0),
    )
    db.add(new_user)
    db.commit()

    return {"id": new_user.id, "username": new_user.username, "is_admin": new_user.is_admin}

@router.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "is_admin": current_user.is_admin,
    }