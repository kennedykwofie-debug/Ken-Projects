"""Shared configuration settings."""
import os
from typing import Optional


class Settings:
    # App
    APP_NAME: str = "DARKWATCH Pro Intelligence API"
    APP_VERSION: str = "2.0.0"
    ENV: str = os.getenv("ENV", "production")
    DEBUG: bool = os.getenv("ENV", "production") == "development"

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "")
    REDIS_URL: str = os.getenv("REDIS_URL", "")

    # Auth
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
    JWT_ALGORITHM: str = "HS256"

    # API Keys
    SHODAN_KEY: Optional[str] = os.getenv("SHODAN_KEY")
    HIBP_KEY: Optional[str] = os.getenv("HIBP_KEY")
    ACLED_KEY: Optional[str] = os.getenv("ACLED_KEY")
    ACLED_EMAIL: Optional[str] = os.getenv("ACLED_EMAIL")
    ABUSEIPDB_KEY: Optional[str] = os.getenv("ABUSEIPDB_KEY")
    FRED_KEY: Optional[str] = os.getenv("FRED_KEY")
    FINNHUB_KEY: Optional[str] = os.getenv("FINNHUB_KEY")
    GROQ_KEY: Optional[str] = os.getenv("GROQ_KEY")

    # Rate limiting
    RATE_LIMIT_DEFAULT: str = "60/minute"
    RATE_LIMIT_PREMIUM: str = "300/minute"

    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")


settings = Settings()
