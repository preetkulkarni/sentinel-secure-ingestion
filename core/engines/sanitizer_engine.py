"""HTML Sanitization Engine for XSS Protection.

This module provides a lightweight wrapper around the `bleach` library to
clean user-submitted text fields. It removes potential Cross-Site Scripting (XSS)
vectors by stripping unauthorized HTML tags and attributes.
"""

import bleach

class SanitizerEngine:
    """A configured HTML cleaner enforcing a strict allowlist of tags."""

    def __init__(self):
        """Initializes the allowed HTML tags and attributes.

        Current Allowlist:
            - Tags: <b>, <i>, <u>, <strong>, <em>, <p>, <br>
            - Attributes: None (all attributes like 'style' or 'onclick' are stripped)
        """
        # Only allow harmless tags (formatting)
        self.allowed_tags = ['b', 'i', 'u', 'strong', 'em', 'p', 'br']
        self.allowed_attrs = {} # No attributes (like onclick or style) allowed

    def clean_payload(self, data: dict, fields: list = None) -> dict:
        """Recursively sanitizes string values within a dictionary.

        This method traverses the dictionary (and nested dictionaries) and applies
        HTML sanitization to string values.

        Args:
            data (dict): The input dictionary containing user data.
            fields (list, optional): A list of specific keys to sanitize.
                If provided, only keys present in this list will be processed.
                If None, all string values in the dictionary are sanitized.

        Returns:
            dict: A new dictionary with sanitized string values. The original
            dictionary is left unmodified.
        """
        cleaned = data.copy()
        
        for key, value in cleaned.items():
            # If specific fields are requested, skip others
            if fields and key not in fields:
                continue

            if isinstance(value, str):
                cleaned[key] = bleach.clean(
                    value, 
                    tags=self.allowed_tags, 
                    attributes=self.allowed_attrs, 
                    strip=True
                )
            elif isinstance(value, dict):
                # Recursive cleaning for nested JSON
                cleaned[key] = self.clean_payload(value, fields)
                
        return cleaned

sanitizer_engine = SanitizerEngine()