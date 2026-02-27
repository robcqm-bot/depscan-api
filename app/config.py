from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "production"
    app_port: int = 8001
    secret_key: str = ""

    @field_validator("secret_key")
    @classmethod
    def secret_key_must_be_set(cls, v: str) -> str:
        if not v or len(v) < 32:
            raise ValueError(
                "SECRET_KEY must be set and at least 32 characters long. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        return v

    database_url: str = ""
    redis_url: str = "redis://localhost:6379/1"

    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_single_starter: str = ""
    stripe_price_single_pro: str = ""
    stripe_price_single_business: str = ""
    stripe_price_deep_starter: str = ""
    stripe_price_deep_pro: str = ""
    stripe_price_deep_business: str = ""
    stripe_price_monitor: str = ""
    stripe_price_unlimited: str = ""

    abuseipdb_api_key: str = ""
    deepseek_api_key: str = ""
    anthropic_api_key: str = ""  # fallback when DeepSeek unavailable

    alert_score_drop_threshold: int = 20
    monitor_scan_interval_hours: int = 6


@lru_cache
def get_settings() -> Settings:
    return Settings()
