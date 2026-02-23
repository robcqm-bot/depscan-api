from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "production"
    app_port: int = 8001
    secret_key: str = ""

    database_url: str = ""
    redis_url: str = "redis://localhost:6379/1"

    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_single: str = ""
    stripe_price_deep: str = ""
    stripe_price_monitor: str = ""
    stripe_price_unlimited: str = ""

    abuseipdb_api_key: str = ""
    whois_api_key: str = ""
    deepseek_api_key: str = ""
    anthropic_api_key: str = ""  # fallback when DeepSeek unavailable

    alert_score_drop_threshold: int = 20
    monitor_scan_interval_hours: int = 6


@lru_cache
def get_settings() -> Settings:
    return Settings()
