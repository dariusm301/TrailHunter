import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String
from sqlalchemy.orm import relationship
from services.utcdatetime import UTCDateTime

from services.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(UTCDateTime(), default=datetime.now(timezone.utc))
    is_admin = Column(Boolean, default=False)
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    probe_tokens = relationship("ProbeToken", back_populates="user", cascade="all, delete-orphan")
    collections = relationship("Collection", back_populates="user", cascade="all, delete-orphan")


class RefreshToken(Base):

    __tablename__ = "refresh_tokens"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=True)
    token_hash = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(UTCDateTime(), nullable=False)
    revoked = Column(Boolean, default=False)
    created_at = Column(UTCDateTime(), default=datetime.now(timezone.utc))

    user = relationship("User", back_populates="refresh_tokens")

class ProbeToken(Base):
    __tablename__ = "probe_tokens"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=True)
    device_identifier = Column(String, nullable=True)
    token_hash = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(UTCDateTime(), nullable=True)
    revoked = Column(Boolean, default=False)
    created_at = Column(UTCDateTime(), default=datetime.now(timezone.utc))
    used_at = Column(UTCDateTime(), nullable=True)
    last_used_at = Column(UTCDateTime(), nullable=True)
    single_use = Column(Boolean, default=False)
    token_type = Column(String, nullable=False, default="hardware") 
    
    collections = relationship("Collection", back_populates="probe_token")
    user = relationship("User", back_populates="probe_tokens")

class Collection(Base):
    __tablename__ = "collections"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname = Column(String, nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    storage_path = Column(String, nullable=True)
    created_at = Column(UTCDateTime(), default=datetime.now(timezone.utc))
    token_id = Column(String, ForeignKey("probe_tokens.id"), nullable=True) 
    probe_token = relationship("ProbeToken", back_populates="collections")
    user = relationship("User", back_populates="collections")