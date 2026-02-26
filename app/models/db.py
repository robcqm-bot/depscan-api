from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True)
    subscription_id = Column(String(40), unique=True, nullable=False, index=True)  # mon_ + uuid4.hex
    api_key_id = Column(Integer, ForeignKey("api_keys.id"), nullable=False)
    skill_url = Column(Text, nullable=True)
    endpoints_json = Column(Text, nullable=False, default="[]")  # JSON-encoded list
    webhook_url = Column(Text, nullable=True)
    alert_threshold = Column(Integer, nullable=False, default=20)
    last_score = Column(Integer, nullable=True)
    last_scan_id = Column(String(40), nullable=True)
    # active / paused (no credits) / cancelled
    status = Column(String(20), nullable=False, default="active")
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    next_check_at = Column(DateTime(timezone=True), nullable=True)

    api_key = relationship("APIKey")
    alerts = relationship("AlertHistory", back_populates="subscription")


class AlertHistory(Base):
    __tablename__ = "alert_history"

    id = Column(Integer, primary_key=True)
    subscription_id = Column(Integer, ForeignKey("subscriptions.id"), nullable=False)
    previous_score = Column(Integer, nullable=False)
    new_score = Column(Integer, nullable=False)
    scan_id = Column(String(40), nullable=False)
    webhook_url = Column(Text, nullable=True)
    # sent / failed / no_webhook
    webhook_status = Column(String(20), nullable=False, default="pending")
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    subscription = relationship("Subscription", back_populates="alerts")


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    tier = Column(String(20), nullable=False, default="single")
    credits_remaining = Column(Integer, nullable=False, default=0)
    stripe_customer_id = Column(String(255), nullable=True)
    stripe_session_id = Column(String(255), nullable=True)
    stripe_subscription_id = Column(String(255), nullable=True, index=True)
    # "pending" → awaiting payment; "active" → usable; "inactive" → suspended
    status = Column(String(20), nullable=False, default="pending")
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    scans = relationship("Scan", back_populates="api_key")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    # dep_ + uuid4 hex, e.g. dep_a1b2c3d4...
    scan_id = Column(String(40), unique=True, nullable=False, index=True)
    api_key_id = Column(Integer, ForeignKey("api_keys.id"), nullable=True)
    skill_url = Column(Text, nullable=True)
    overall_score = Column(Integer, nullable=True)
    scan_status = Column(String(20), nullable=True)  # SAFE/CAUTION/RISK/CRITICAL
    recommendation = Column(String(50), nullable=True)
    scan_type = Column(String(20), nullable=False, default="single")
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)
    processing_time_ms = Column(Integer, nullable=True)

    api_key = relationship("APIKey", back_populates="scans")
    endpoint_results = relationship("EndpointResultDB", back_populates="scan")


class EndpointResultDB(Base):
    __tablename__ = "endpoint_results"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    url = Column(Text, nullable=False)
    status = Column(String(20), nullable=False)
    latency_ms = Column(Integer, nullable=True)
    ssl_expires_days = Column(Integer, nullable=True)
    ssl_valid = Column(Boolean, nullable=True)
    domain_age_days = Column(Integer, nullable=True)
    domain_owner_changed = Column(Boolean, nullable=True)
    abuse_score = Column(Integer, nullable=False, default=0)
    in_blacklist = Column(Boolean, nullable=False, default=False)
    flags = Column(Text, nullable=False, default="[]")  # JSON-encoded list
    score = Column(Integer, nullable=False, default=50)

    scan = relationship("Scan", back_populates="endpoint_results")
