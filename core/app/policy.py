"""Dynamic Policy Enforcement Engine.

This module loads and manages the operational security policies for the Sentinel
platform. Unlike static environment variables, these policies are designed to be
loaded from an external YAML file (`sentinel.yaml`), allowing for complex,
nested configurations and potential runtime updates.

Typical Usage:
    from app.policy import policy
    if policy.scanner_enabled:
        ...
"""

import yaml
import os
import logging
from typing import List

logger = logging.getLogger("sentinel.policy")

class SentinelPolicy:
    """A wrapper around the YAML configuration file enforcing default behaviors.

    This class parses the `sentinel.yaml` file and exposes typed properties for
    application logic to consume. It implements a 'Fail Safe' mechanism where
    missing configurations fall back to secure defaults.
    """

    def __init__(self, config_path: str = "/app/sentinel.yaml"):
        """Initializes the policy engine.

        Args:
            config_path (str): Absolute path to the configuration file.
                Defaults to "/app/sentinel.yaml".
        """
        self.config_path = config_path
        self._config = {}
        self.reload()

    def reload(self):
        """Loads or reloads the configuration from disk.

        If the configuration file is missing or invalid, the system falls back
        to `_default_config()` and logs a warning. This prevents the application
        from crashing due to misconfiguration.
        """
        if not os.path.exists(self.config_path):
            logger.warning(f"⚠️ Policy file not found at {self.config_path}. Using Defaults.")
            self._config = self._default_config()
            return

        try:
            with open(self.config_path, "r") as f:
                self._config = yaml.safe_load(f)
            logger.info(f"✅ Security Policy loaded from {self.config_path}")
        except Exception as e:
            logger.critical(f"❌ Failed to load security policy: {e}")
            self._config = self._default_config()

    def _default_config(self):
        """Returns the hardcoded 'Safe Mode' configuration.

        These defaults are used if the external YAML file cannot be loaded.
        They prioritize security (enabling all scanners) and standard limits.
        """
        return {
            "services": {
                "scanner": True,
                "privacy": True,
                "sanitizer": True
            },
            "file_security": {
                "max_size_mb": 50,
                "allowed_mime_types": ["text/plain"]
            },
            "privacy": {
                "pii_entities": ["EMAIL_ADDRESS"],
                "score_threshold": 0.5
            },
            "sanitization": {
                "allowed_tags": [],
                "allowed_attributes": {}
            }
        }

    # --- Service Toggles ---
    @property
    def scanner_enabled(self) -> bool:
        """Feature flag: Enable/Disable the AV scanning engine."""
        return self._config.get("services", {}).get("scanner", True)

    @property
    def privacy_enabled(self) -> bool:
        """Feature flag: Enable/Disable PII scrubbing."""
        return self._config.get("services", {}).get("privacy", True)

    @property
    def sanitizer_enabled(self) -> bool:
        """Feature flag: Enable/Disable HTML sanitization."""
        return self._config.get("services", {}).get("sanitizer", True)

    # --- Existing Properties ---
    @property
    def max_file_size_bytes(self) -> int:
        """Calculates the max allowed file size in bytes.

        Converts the YAML 'max_size_mb' (integer) into bytes.
        """
        mb = self._config.get("file_security", {}).get("max_size_mb", 50)
        return mb * 1024 * 1024

    @property
    def allowed_mime_types(self) -> List[str]:
        """Returns the list of permitted MIME types for file ingestion."""
        return self._config.get("file_security", {}).get("allowed_mime_types", [])

    @property
    def pii_entities(self) -> List[str]:
        """Returns the list of PII entities (e.g., 'US_SSN') to look for."""
        return self._config.get("privacy", {}).get("pii_entities", [])

    @property
    def pii_threshold(self) -> float:
        """Returns the confidence score threshold for PII detection."""
        return self._config.get("privacy", {}).get("score_threshold", 0.4)

    @property
    def allowed_tags(self) -> List[str]:
        """Returns the allowlist of HTML tags for the sanitizer."""
        return self._config.get("sanitization", {}).get("allowed_tags", [])

policy = SentinelPolicy()