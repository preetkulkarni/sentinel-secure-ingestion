"""Configuration management for the Sentinel platform.

This module defines the Pydantic settings and data models used throughout
the application. It handles environment variable loading, validation,
and structured data definitions for API payloads.
"""

from pydantic import SecretStr, BaseModel
from typing import Dict, Any, List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """Global application settings loaded from environment variables.

    This class leverages Pydantic's BaseSettings to automatically load
    and validate configuration from a .env file or system environment variables.

    Attributes:
        PROJECT_NAME (str): The name of the application.
        MONGO_URI (SecretStr): The full connection string for MongoDB.
        MONGO_DB_NAME (str): The specific database name to use.
        SCANNER_URL (SecretStr): The internal URL for the sentinel-scanner service.
        SCANNER_API_KEY (SecretStr): Authentication key for the scanner service.
        SENTINEL_MASTER_KEY (SecretStr): The master key used for internal encryption/decryption.
        PRESIDIO_ANALYZER_URL (str): URL for the PII analyzer service.
        PRESIDIO_ANONYMIZER_URL (str): URL for the PII anonymizer service.
        S3_ENDPOINT (SecretStr): The endpoint URL for the S3-compatible storage (e.g., MinIO).
        S3_ACCESS_KEY (SecretStr): Access key ID for S3 storage.
        S3_SECRET_KEY (SecretStr): Secret access key for S3 storage.
        S3_BUCKET_QUARANTINE (str): Bucket name for storing potentially malicious files.
        S3_BUCKET_CLEAN (str): Bucket name for storing validated safe files.
    """
    PROJECT_NAME: str = "Sentinel"

    # Infrastructure
    MONGO_URI: SecretStr
    MONGO_DB_NAME: str = "sentinel_db"
    SCANNER_URL: SecretStr
    SCANNER_API_KEY: SecretStr  

    # Master key
    SENTINEL_MASTER_KEY: SecretStr

    # Presidio (PII Engine)
    PRESIDIO_ANALYZER_URL: str
    PRESIDIO_ANONYMIZER_URL: str

    # MinIO / S3
    S3_ENDPOINT: SecretStr
    S3_ACCESS_KEY: SecretStr
    S3_SECRET_KEY: SecretStr
    S3_BUCKET_QUARANTINE: str = "quarantine"
    S3_BUCKET_CLEAN: str = "safe-files"

    # This allows loading from a .env file automatically
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8",
        case_sensitive=True
    )

class DataPayload(BaseModel):
    """Represents the standard data ingestion payload structure.

    This model validates the incoming JSON body for API endpoints that
    handle data ingestion.

    Attributes:
        collection (str): The target MongoDB collection where data should be stored.
        payload (Dict[str, Any]): The actual data content to be processed/stored.
        sanitize_fields (Optional[List[str]]): A list of specific field names within
            the payload that require XSS sanitization. Defaults to None.
        scrub_pii (bool): Flag indicating if PII scrubbing should be performed
            on the payload. Defaults to False.
    """
    collection: str               # Target MongoDB collection
    payload: Dict[str, Any]       # The data content
    sanitize_fields: Optional[List[str]] = None # specific fields to clean XSS
    scrub_pii: bool = False

settings = Settings()