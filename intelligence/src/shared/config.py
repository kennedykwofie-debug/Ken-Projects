"""Shared configuration settings."""
import os
from typing import Optional


class Settings:
    APP_NAME: str = "DARKWATCH Pro Intelligence API"
    APP_VERSION: str = "2.0.0"
    ENV: str = os.getenv("ENV", "production")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "")
    REDIS_URL: str = os.getenv("REDIS_URL", "")
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
    JWT_ALGORITHM: str = "HS256"
    cache_ttl: int = 300
    shodan_key: Optional[str] = os.getenv("SHODAN_KEY")
    hibp_key: Optional[str] = os.getenv("HIBP_KEY")
    acled_key: Optional[str] = os.getenv("ACLED_KEY")
    acled_email: Optional[str] = os.getenv("ACLED_EMAIL")
    abuseipdb_key: Optional[str] = os.getenv("ABUSEIPDB_KEY")
    fred_key: Optional[str] = os.getenv("FRED_KEY")
    finnhub_key: Optional[str] = os.getenv("FINNHUB_KEY")
    groq_key: Optional[str] = os.getenv("GROQ_KEY")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")


settings = Settings()
