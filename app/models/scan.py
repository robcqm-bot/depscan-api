from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, field_validator, model_validator


class ScanRequest(BaseModel):
    skill_url: Optional[str] = None
    endpoints: Optional[List[str]] = None
    scan_type: Literal["single", "deep"] = "single"
    callback_url: Optional[str] = None

    @field_validator("endpoints")
    @classmethod
    def validate_endpoints(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        if len(v) > 50:
            raise ValueError("Maximum 50 endpoints per request")
        for url in v:
            if len(url) > 2048:
                raise ValueError("URL exceeds maximum length of 2048 characters")
        return v

    @model_validator(mode="after")
    def must_have_source(self):
        if not self.endpoints and not self.skill_url:
            raise ValueError("Se requiere skill_url o endpoints")
        return self


class EndpointResult(BaseModel):
    url: str
    status: Literal["UP", "DOWN", "TIMEOUT", "SSL_ERROR", "UNKNOWN"]
    latency_ms: Optional[int] = None
    ssl_expires_days: Optional[int] = None
    ssl_valid: Optional[bool] = None
    domain_age_days: Optional[int] = None        # Fase 1: WHOIS
    domain_owner_changed: Optional[bool] = None  # Fase 1: WHOIS
    abuse_score: int = 0                          # Fase 1: AbuseIPDB
    in_blacklist: bool = False
    flags: List[str] = []
    score: int = 50


class AIInsight(BaseModel):
    summary: str
    key_risk: str
    action: Literal["PROCEED", "REVIEW", "BLOCK"]


class ScanResponse(BaseModel):
    scan_id: str
    skill: Optional[str] = None
    overall_score: int
    status: Literal["SAFE", "CAUTION", "RISK", "CRITICAL", "PENDING"]
    endpoints: List[EndpointResult]
    recommendation: Literal["SAFE_TO_INSTALL", "REVIEW_BEFORE_INSTALL", "DO_NOT_INSTALL"]
    scan_type: str
    timestamp: datetime
    processing_time_ms: int
    ai_insight: Optional[AIInsight] = None  # present when DEEPSEEK_API_KEY is configured


class MonitorSubscribeRequest(BaseModel):
    skill_url: Optional[str] = None
    endpoints: Optional[List[str]] = None
    webhook_url: Optional[str] = None
    alert_threshold: int = 20

    @model_validator(mode="after")
    def must_have_source(self):
        if not self.endpoints and not self.skill_url:
            raise ValueError("Se requiere skill_url o endpoints")
        return self


class MonitorSubscribeResponse(BaseModel):
    subscription_id: str
    status: str
    skill_url: Optional[str]
    endpoints: List[str]
    webhook_url: Optional[str]
    alert_threshold: int
    next_check_at: datetime
    created_at: datetime


class AlertRecord(BaseModel):
    previous_score: int
    new_score: int
    scan_id: str
    webhook_status: str
    created_at: datetime


class MonitorHistoryEntry(BaseModel):
    scan_id: str
    overall_score: int
    status: str
    timestamp: datetime
    alerts: List[AlertRecord] = []


class MonitorHistoryResponse(BaseModel):
    subscription_id: str
    skill_url: Optional[str]
    current_status: str
    last_score: Optional[int]
    history: List[MonitorHistoryEntry]


class CheckoutRequest(BaseModel):
    tier: Literal[
        "single_starter", "single_pro", "single_business",
        "deep_starter", "deep_pro", "deep_business",
        "monitor", "unlimited",
    ]


class CheckoutResponse(BaseModel):
    checkout_url: str
    api_key: str
    note: str = "Save your API key now — it will not be shown again."
