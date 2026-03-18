import os
from typing import List
from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "DARKWATCH Pro Intelligence Service"
    version: str = "2.0.0"
    env: str = "production"

    # Auth
    api_keys: str = ""
    allowed_origins: str = ""

    # Data source keys
    shodan_key: str = ""
    hibp_key: str = ""
    otx_api_key: str = ""
    acled_key: str = ""
    acled_email: str = ""
    abuseipdb_key: str = ""
    fred_key: str = ""
    finnhub_key: str = ""
    groq_key: str = ""

    # Infrastructure
    redis_url: str = ""
    cache_ttl: int = 300
    log_level: str = "INFO"

    def get_api_keys(self) -> List[str]:
        return [k.strip() for k in self.api_keys.split(",") if k.strip()]

    def get_allowed_origins(self) -> List[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
