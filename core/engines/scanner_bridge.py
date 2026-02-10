"""Bridge interface for the Sentinel Scanner microservice.

This module handles the HTTP communication with the external `sentinel-scanner`
service. It implements an asynchronous **Polling Pattern**:
1.  **Submit**: Uploads the file to the scanner and receives a Task ID.
2.  **Poll**: Periodically checks the status of the Task ID.
3.  **Result**: Aggregates verdicts from multiple engines (ClamAV, Yara).
"""

import asyncio
import logging
import os
import time
from typing import Optional

import httpx
from fastapi import HTTPException, status
from pydantic import BaseModel, ValidationError

from app.config import settings

logger = logging.getLogger("sentinel.scanner")

# --- Models ---
class ClamAVResult(BaseModel):
    """Represents the raw result from the ClamAV engine."""
    status: str             # e.g., "clean", "infected", "error"
    details: Optional[str] = None # Name of the virus found, if any

class YaraResult(BaseModel):
    """Represents the raw result from the Yara engine."""
    matches: list[str] = [] # List of matched rule names

class ScanResults(BaseModel):
    """Container for the combined results of all scanning engines."""
    clamav: ClamAVResult
    yara: YaraResult

class ScanResponse(BaseModel):
    """Represents the API response structure from the scanner service."""
    status: str                     # "pending", "complete", or "error"
    result: Optional[ScanResults] = None
    detail: Optional[str] = None    # Error message if status is "error"

# --- Configuration ---
POLL_INTERVAL = 1.0
# We allow the scanner logic 45s total, so we need the HTTP requests 
# to not timeout before the logic decides to quit.
SCAN_TIMEOUT = 45.0 

async def scan_file(client: httpx.AsyncClient, file_content: bytes, filename: str) -> bool:
    """Submits a file for security scanning and awaits the verdict.

    This function blocks (asynchronously) until the scan is complete or times out.
    It enforces a "Zero Trust" policy: if either ClamAV or Yara detects a threat,
    the file is rejected.

    Args:
        client (httpx.AsyncClient): The shared HTTP client session.
        file_content (bytes): The raw binary content of the file.
        filename (str): The original filename (used for logging/reporting).

    Returns:
        bool: True only if the file is confirmed "clean" by ALL engines.

    Raises:
        HTTPException (503): If the scanner service is unavailable or warming up.
        HTTPException (504): If the scan takes longer than `SCAN_TIMEOUT`.
        HTTPException (400): If **Malware** or **Yara Rules** are detected.
        HTTPException (500): If the scanner returns an invalid or empty response.
    """
    safe_filename = os.path.basename(filename) or "unknown_file"
    headers = {"X-API-Key": settings.SCANNER_API_KEY.get_secret_value()}
    
    # 1. Submit File
    try:
        # We override the client's default 15s timeout here because 
        # uploading large files takes time.
        resp = await client.post(
            f"{settings.SCANNER_URL.get_secret_value()}/scan",
            files={"file": (safe_filename, file_content)},
            headers=headers,
            timeout=30.0 
        )

        if resp.status_code == 401:
            logger.critical("Scanner Auth Failed. Check API Key.")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Scanner Configuration Error")
        
        resp.raise_for_status()
        task_id = resp.json().get("task_id")
        
        if not task_id:
            raise ValueError("Scanner did not return a task_id")

    except httpx.HTTPError as e:
        logger.error(f"Scanner Connection Error: {e}")
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Scanner unavailable")

    # 2. Poll for Results
    start_time = time.monotonic()
    
    while True:
        if time.monotonic() - start_time > SCAN_TIMEOUT:
            logger.error(f"Scanner timed out processing {task_id}")
            raise HTTPException(status.HTTP_504_GATEWAY_TIMEOUT, "Security scan timed out")

        try:
            # Short timeout for status checks is fine
            check_resp = await client.get(
                f"{settings.SCANNER_URL.get_secret_value()}/results/{task_id}", 
                headers=headers,
                timeout=5.0
            )
            check_resp.raise_for_status()
            data = ScanResponse(**check_resp.json())

        except (ValidationError, httpx.HTTPError) as e:
            logger.error(f"Error fetching results for {task_id}: {e}")
            # We retry on network blips, but you could fail fast here if strict
            await asyncio.sleep(POLL_INTERVAL)
            continue

        if data.status == "pending":
            await asyncio.sleep(POLL_INTERVAL)
            continue
        
        elif data.status == "error":
            logger.error(f"Scanner internal error: {data.detail}")
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "File could not be scanned")
            
        elif data.status == "complete":
            if not data.result:
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Empty scan result")

            clam_clean = data.result.clamav.status == "clean"
            yara_clean = len(data.result.yara.matches) == 0

            if clam_clean and yara_clean:
                return True

            # Aggregate threats for the logs
            threats = []
            if not clam_clean:
                threats.append(f"ClamAV: {data.result.clamav.details}")
            if not yara_clean:
                threats.append(f"Yara Rules: {data.result.yara.matches}")
            
            if "ClamAV: ClamAV Engine is warming up" in threats:
                logger.warning("⛔ ClamAV is warming up, try again later.")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Security scanner is warming up, please try again later."
                )

            logger.warning(f"⛔ Malware Blocked: {safe_filename} | {threats}")
            
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Security Validation Failed: {'; '.join(threats)}"
            )

        else:
            logger.warning(f"Unknown status: {data.status}")
            await asyncio.sleep(POLL_INTERVAL)