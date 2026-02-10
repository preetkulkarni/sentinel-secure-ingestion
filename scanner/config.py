"""Configuration settings for the Sentinel Scanner service.

This module defines the environment-based configuration for the antivirus
scanning service, including connection details for the ClamAV daemon and
paths for local YARA signatures.
"""

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

class AVSettings(BaseSettings):
    """Application settings loaded from environment variables.

    Attributes:
        SCANNER_API_KEY (SecretStr): The shared secret used to authenticate
            requests from the Sentinel Core service.
        CLAMAV_HOST (str): The hostname or IP address of the ClamAV daemon
            (clamd). Defaults to 'clamav-service'.
        CLAMAV_PORT (int): The network port for the ClamAV daemon. Defaults to 3310.
        YARA_RULES_PATH (str): The filesystem path where YARA rule files (.yar)
            are stored.
    """
    # API Key for authentication
    SCANNER_API_KEY: SecretStr

    # New Network Config
    CLAMAV_HOST: str = "clamav-service" # Matches docker-compose service name
    CLAMAV_PORT: int = 3310

    # YARA
    YARA_RULES_PATH: str = "/app/signature-base/yara"

    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8",
        case_sensitive=True
    )

avsettings = AVSettings()