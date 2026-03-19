"""Database models for DARKWATCH multi-tenant platform."""
import uuid
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import (Column, String, Boolean, DateTime, Integer, Text,
    ForeignKey, Enum, JSON, UniqueConstraint, Index)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.sql import func

Base = declarative_base()

def gen_uuid():
    return str(uuid.uuid4())

class OrgPlan(str, PyEnum):
    FREE = "free"; PRO = "pro"; ENTERPRISE = "enterprise"

class UserRole(str, PyEnum):
    SUPERADMIN = "superadmin"; ADMIN = "admin"; ANALYST = "analyst"; USER = "user"

class AssetType(str, PyEnum):
    DOMAIN = "domain"; IP = "ip"; CIDR = "cidr"; ASN = "asn"; EMAIL = "email"; KEYWORD = "keyword"

class AlertSeverity(str, PyEnum):
    CRITICAL = "critical"; HIGH = "high"; MEDIUM = "medium"; LOW = "low"; INFO = "info"

class AlertType(str, PyEnum):
    CREDENTIAL_BREACH = "credential_breach"; C2_DETECTED = "c2_detected"
    CVE_EXPLOITED = "cve_exploited"; GEO_ESCALATION = "geo_escalation"
    DARK_WEB_MENTION = "dark_web_mention"; ASSET_EXPOSED = "asset_exposed"; THREAT_ACTOR = "threat_actor"

class Organisation(Base):
    __tablename__ = "organisations"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), nullable=False, unique=True)
    plan = Column(Enum(OrgPlan), default=OrgPlan.FREE, nullable=False)
    industry = Column(String(100), nullable=True)
    country = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    settings = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    users = relationship("User", back_populates="org", cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="org", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="org", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="org", cascade="all, delete-orphan")
    posture_scores = relationship("PostureScore", back_populates="org", cascade="all, delete-orphan")
    __table_args__ = (Index("ix_orgs_slug", "slug"),)

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    org_id = Column(UUID(as_uuid=False), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False)
    email = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)
    preferences = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    org = relationship("Organisation", back_populates="users")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    __table_args__ = (
        UniqueConstraint("org_id", "email", name="uq_user_org_email"),
        Index("ix_users_email", "email"), Index("ix_users_org", "org_id"),)

class UserSession(Base):
    __tablename__ = "user_sessions"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(255), nullable=False, unique=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user = relationship("User", back_populates="sessions")
    __table_args__ = (Index("ix_sessions_token", "token_hash"),)

class Asset(Base):
    __tablename__ = "assets"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    org_id = Column(UUID(as_uuid=False), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False)
    type = Column(Enum(AssetType), nullable=False)
    value = Column(String(500), nullable=False)
    label = Column(String(255), nullable=True)
    tags = Column(JSON, default=list)
    is_active = Column(Boolean, default=True)
    last_scanned = Column(DateTime(timezone=True), nullable=True)
    scan_data = Column(JSON, default=dict)
    created_by = Column(UUID(as_uuid=False), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    org = relationship("Organisation", back_populates="assets")
    scan_results = relationship("ScanResult", back_populates="asset", cascade="all, delete-orphan")
    __table_args__ = (
        UniqueConstraint("org_id", "type", "value", name="uq_asset_org_type_value"),
        Index("ix_assets_org", "org_id"), Index("ix_assets_type", "type"),)

class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    asset_id = Column(UUID(as_uuid=False), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    scan_type = Column(String(50), nullable=False)
    result = Column(JSON, default=dict)
    risk_score = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    asset = relationship("Asset", back_populates="scan_results")
    __table_args__ = (Index("ix_scans_asset", "asset_id"),)

class PostureScore(Base):
    __tablename__ = "posture_scores"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    org_id = Column(UUID(as_uuid=False), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False)
    score = Column(Integer, default=100)
    grade = Column(String(2), default="A")
    breakdown = Column(JSON, default=dict)
    recommendations = Column(JSON, default=list)
    computed_at = Column(DateTime(timezone=True), server_default=func.now())
    org = relationship("Organisation", back_populates="posture_scores")
    __table_args__ = (Index("ix_posture_org", "org_id"),)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    org_id = Column(UUID(as_uuid=False), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False)
    type = Column(Enum(AlertType), nullable=False)
    severity = Column(Enum(AlertSeverity), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    data = Column(JSON, default=dict)
    asset_id = Column(UUID(as_uuid=False), nullable=True)
    is_read = Column(Boolean, default=False)
    is_resolved = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    org = relationship("Organisation", back_populates="alerts")
    __table_args__ = (Index("ix_alerts_org", "org_id"), Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_read", "is_read"),)

class APIKey(Base):
    __tablename__ = "api_keys"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    org_id = Column(UUID(as_uuid=False), ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    key_hash = Column(String(255), nullable=False, unique=True)
    key_prefix = Column(String(10), nullable=False)
    permissions = Column(JSON, default=list)
    is_active = Column(Boolean, default=True)
    last_used = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(UUID(as_uuid=False), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    org = relationship("Organisation", back_populates="api_keys")
    __table_args__ = (Index("ix_apikeys_org", "org_id"),)
