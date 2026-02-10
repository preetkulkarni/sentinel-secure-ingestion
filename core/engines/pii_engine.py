"""PII Detection and Anonymization Engine.

This module acts as an asynchronous client for the Microsoft Presidio services.
It orchestrates a two-step privacy pipeline:
1.  **Analyze**: Sends text to the Analyzer service to identify PII entities (SSN, Email, etc.).
2.  **Anonymize**: Sends the analysis results to the Anonymizer service to replace
    real data with placeholders (e.g., [REDACTED-EMAIL]).

Security Policy:
    - This engine follows a "Fail Closed" policy. If the external Presidio services
      are unreachable, the operation raises an exception to prevent unscrubbed
      data from persisting.
"""

import httpx
import logging
from app.config import settings

logger = logging.getLogger(__name__)

class PIIEngine:
    """Manages the network interactions with Microsoft Presidio containers."""

    def __init__(self):
        """Initializes the service URLs from the global configuration settings."""
        # Endpoints for the Microsoft containers
        self.analyzer_url = f"{settings.PRESIDIO_ANALYZER_URL}/analyze"
        self.anonymizer_url = f"{settings.PRESIDIO_ANONYMIZER_URL}/anonymize"

    async def scrub(self, text: str) -> str:
        """Sanitizes a string by detecting and redacting Personally Identifiable Information.

        The current configuration detects:
        - CREDIT_CARD
        - EMAIL_ADDRESS
        - IP_ADDRESS
        - PHONE_NUMBER
        - US_SSN
        - PERSON (Names)

        Args:
            text (str): The raw input text containing potential PII.

        Returns:
            str: The sanitized text with PII replaced by placeholders (e.g., "[REDACTED-SSN]").
                 Returns the original text if input is None or not a string.

        Raises:
            RuntimeError: If the Presidio services are unavailable or return an error.
                This enforces a "Fail Closed" security posture.
        """
        if not text or not isinstance(text, str):
            return text

        async with httpx.AsyncClient() as client:
            try:
                # 1. Analyze: Ask Presidio to find PII locations
                analyze_payload = {
                    "text": text,
                    "language": "en",
                    "score_threshold": 0.4,
                    "entities": [
                        "CREDIT_CARD", "EMAIL_ADDRESS", "IP_ADDRESS", 
                        "PHONE_NUMBER", "US_SSN", "PERSON"
                    ]
                }
                
                resp_analyze = await client.post(self.analyzer_url, json=analyze_payload)
                resp_analyze.raise_for_status()
                findings = resp_analyze.json()

                if not findings:
                    return text # No PII found

                # 2. Anonymize: Ask Presidio to replace findings with placeholders
                anonymize_payload = {
                    "text": text,
                    "analyzer_results": findings,
                    "anonymizers": {
                        "DEFAULT": {"type": "replace", "new_value": "[REDACTED]"},
                        "PHONE_NUMBER": {"type": "replace", "new_value": "[REDACTED-PHONE]"},
                        "EMAIL_ADDRESS": {"type": "replace", "new_value": "[REDACTED-EMAIL]"},
                        "US_SSN": {"type": "replace", "new_value": "[REDACTED-SSN]"},
                        "CREDIT_CARD": {"type": "replace", "new_value": "[REDACTED-CC]"}
                    }
                }

                resp_anon = await client.post(self.anonymizer_url, json=anonymize_payload)
                resp_anon.raise_for_status()
                
                return resp_anon.json().get("text")

            except Exception as e:
                logger.critical(f"⛔ PII Scrubber Failed: {e}")
                # Raise an error so the API rejects the request instead of leaking data.
                raise RuntimeError("Privacy engine unavailable. Request halted for safety.")