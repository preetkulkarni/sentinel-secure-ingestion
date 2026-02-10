"""Official Python Client for the Sentinel Platform.

This module provides a high-level, Pythonic interface for interacting with the
Sentinel Core API. It handles authentication, error parsing, and efficient
streaming for file uploads/downloads.

Typical Usage:
    client = SentinelClient(base_url="http://localhost:8000")
    client.ingest_file("malware_sample.exe")
"""

import os
import requests
from typing import Dict, List, Any, Union

# 1. Custom Exceptions for better Developer Experience (DX)
class SentinelError(Exception):
    """Base exception for all client-side Sentinel errors."""
    pass

class SentinelAPIError(SentinelError):
    """Exception raised when the API returns an error response (4xx or 5xx).

    Attributes:
        message (str): The error description.
        status_code (int): The HTTP status code returned by the API.
    """
    def __init__(self, message, status_code):
        super().__init__(f"{message} (Status: {status_code})")
        self.status_code = status_code

class SentinelClient:
    """A synchronous client wrapper for the Sentinel REST API."""

    def __init__(self, base_url: str = None, api_key: str = None):
        """Initializes the client with connection details.

        Args:
            base_url (str, optional): The root URL of the Sentinel Core service.
                Defaults to "http://localhost:8000" or the SENTINEL_URL env var.
            api_key (str, optional): The API Key for authentication (if required).
                Defaults to the SENTINEL_API_KEY env var.

        Raises:
            SentinelError: If the base_url is missing and cannot be inferred.
        """
        # Remove trailing slash to prevent double-slash URLs (e.g. http://host//ingest)
        self.base_url = (base_url or os.getenv("SENTINEL_URL", "http://localhost:8000")).rstrip("/")
        self.api_key = api_key or os.getenv("SENTINEL_API_KEY")

        if not self.base_url:
            raise SentinelError("Sentinel Base URL is required. Set SENTINEL_URL env var.")

    def _get_headers(self) -> Dict[str, str]:
        """Constructs the standard HTTP headers for requests."""
        headers = {}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _handle_error(self, resp: requests.Response):
        """Parses raw HTTP responses to raise structured exceptions.

        It attempts to extract specific error details from the FastAPI JSON body
        before falling back to the raw text body.

        Raises:
            SentinelAPIError: If the status code indicates failure (4xx/5xx).
            SentinelError: If a network connection error occurs.
        """
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            # Try to get the detailed error message from FastAPI JSON
            try:
                error_detail = resp.json().get("detail", str(e))
            except Exception:
                error_detail = resp.text or str(e)
            
            raise SentinelAPIError(error_detail, resp.status_code) from e
        except requests.exceptions.RequestException as e:
            raise SentinelError(f"Connection Failed: {e}") from e

    def ingest_file(self, file_obj: Union[str, Any], filename: str = None) -> Dict[str, Any]:
        """Uploads a file to the Secure File Pipeline.

        This method handles both file paths (strings) and open file objects.
        If a path is provided, it handles opening and closing the file automatically.

        Args:
            file_obj (Union[str, Any]): A file path (str) or a file-like object
                (opened in binary mode).
            filename (str, optional): The name of the file to report to the API.
                If not provided, it is inferred from the file path or object.

        Returns:
            Dict[str, Any]: The JSON response from the API, typically containing
            the new `file_id`.
        """
        url = f"{self.base_url}/ingest/file"
        
        # Handle file paths (string) automatically
        should_close = False
        if isinstance(file_obj, str):
            if not filename:
                filename = os.path.basename(file_obj)
            file_obj = open(file_obj, "rb")
            should_close = True

        # Fallback for open file objects
        if not filename and hasattr(file_obj, "name"):
            filename = os.path.basename(file_obj.name)

        files = {"file": (filename or "unknown_file", file_obj)}

        try:
            resp = requests.post(url, files=files, headers=self._get_headers())
            self._handle_error(resp)
            return resp.json()
        finally:
            if should_close:
                file_obj.close()

    def ingest_data(
        self,
        collection: str,
        payload: Dict[str, Any],
        sanitize_fields: List[str] = None,
        scrub_pii: bool = False,
    ) -> Dict[str, Any]:
        """Submits a JSON payload to the Secure Data Pipeline.

        Args:
            collection (str): The target database collection name.
            payload (Dict[str, Any]): The actual data dictionary to store.
            sanitize_fields (List[str], optional): A list of field names that
                require HTML sanitization (XSS protection).
            scrub_pii (bool, optional): If True, runs the payload through the
                PII scrubbing engine (Presidio) before storage.

        Returns:
            Dict[str, Any]: The JSON response containing the new `doc_id`.
        """
        url = f"{self.base_url}/ingest/data"

        body = {
            "collection": collection,
            "payload": payload,
            "sanitize_fields": sanitize_fields,
            "scrub_pii": scrub_pii,
        }

        resp = requests.post(url, json=body, headers=self._get_headers())
        self._handle_error(resp)
        return resp.json()

    def retrieve_file(self, file_id: str, output_path: str = None) -> Union[bytes, None]:
        """Securely retrieves and decrypts a file from storage.

        This method supports streaming to handle large files efficiently.

        Args:
            file_id (str): The unique ID of the file to retrieve.
            output_path (str, optional): If provided, the file content is streamed
                directly to this path on disk. If None, the content is returned
                in memory as bytes.

        Returns:
            Union[bytes, None]: The file content as bytes if `output_path` is None.
            Returns None if the file was written to disk.

        Raises:
            SentinelAPIError: If the file ID is invalid or not found.
        """
        url = f"{self.base_url}/retrieve/file/{file_id}"

        # FIX: stream=True is essential for large files
        with requests.get(url, headers=self._get_headers(), stream=True) as resp:
            self._handle_error(resp)

            if output_path:
                with open(output_path, "wb") as f:
                    # FIX: Iterate in 8KB chunks to keep RAM usage low
                    for chunk in resp.iter_content(chunk_size=8192):
                        f.write(chunk)
                return None  # Standard practice: void return if side-effect (saving) occurred
            else:
                return resp.content