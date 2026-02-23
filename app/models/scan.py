from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, field_validator, model_validator


class ScanRequest(BaseModel):
    skill_url: Optional[str] = None
    endpoints: Optional[List[str]] = None
    scan_type: Literal["single", "deep"] = "single"
    callback_url: Optional[str] = None

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
    status: Literal["SAFE", "CAUTION", "RISK", "CRITICAL"]
    endpoints: List[EndpointResult]
    recommendation: Literal["SAFE_TO_INSTALL", "REVIEW_BEFORE_INSTALL", "DO_NOT_INSTALL"]
    scan_type: str
    timestamp: datetime
    processing_time_ms: int
    ai_insight: Optional[AIInsight] = None  # present when DEEPSEEK_API_KEY is configured


class CheckoutRequest(BaseModel):
    tier: Literal["single", "deep"] = "single"
    quantity: int = 10

    @field_validator("quantity")
    @classmethod
    def quantity_in_range(cls, v: int) -> int:
        if v < 1 or v > 10_000:
            raise ValueError("quantity must be between 1 and 10,000")
        return v


class CheckoutResponse(BaseModel):
    checkout_url: str
    api_key: str
    note: str = "Save your API key now — it will not be shown again."
