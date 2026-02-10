"""Sentinel Scanner Service API.

This module implements an asynchronous, non-blocking AV scanning service.
It uses an **Asynchronous Task Queue** pattern:
1.  **Ingest**: Files are uploaded to a temporary location (`/tmp`).
2.  **Queue**: A background task is spawned to process the file.
3.  **Poll**: The client receives a `task_id` and polls the results endpoint.

State Management:
    - Results are stored in an in-memory `TTLCache`.
    - Results expire after 10 minutes (600s) to prevent memory leaks.
    - No persistent database is used to keep the scanner stateless and fast.
"""

import os
import shutil
import uuid
import logging
from contextlib import asynccontextmanager

from fastapi import (
    BackgroundTasks,
    FastAPI,
    File,
    HTTPException,
    Security,
    UploadFile,
    status,
)
from fastapi.security import APIKeyHeader
from cachetools import TTLCache

from config import avsettings
from scanner import perform_full_scan, compile_yara_rules

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel.api")

# Security Headers
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# In-Memory Storage with TTL (Time To Live)
# Stores up to 1000 results. Each result expires after 10 minutes (600s).
# This prevents the "Infinite Memory Growth" crash.
RESULTS_CACHE = TTLCache(maxsize=1000, ttl=600)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for the FastAPI application.

    - **Startup**: Compiles YARA rules once so they are cached in memory.
    - **Shutdown**: Logs shutdown sequence.
    """
    # Startup: Load Rules
    logger.info("⚡ Scanner Service Starting...")
    compile_yara_rules()
    yield
    # Shutdown
    logger.info("🛑 Scanner Service Stopping...")

app = FastAPI(
    title="Sentinel Scanner",
    description="High-performance AV Microservice",
    lifespan=lifespan
)

async def validate_api_key(header_key: str = Security(API_KEY_HEADER)):
    """Validates the 'X-API-Key' header against environment settings.

    Args:
        header_key (str): The value extracted from the HTTP header.

    Returns:
        str: The validated key if successful.

    Raises:
        HTTPException (401): If the key is missing or invalid.
    """
    # Use Constant Time Comparison if possible, but for simple strings:
    expected = avsettings.SCANNER_API_KEY.get_secret_value()
    if header_key == expected:
        return header_key
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API Key",
    )

def background_scan_task(file_path: str, task_id: str):
    """Worker function executed in the background.

    Performs the CPU-intensive scanning operations and updates the
    `RESULTS_CACHE` with the final verdict.

    Args:
        file_path (str): Path to the temporary file on disk.
        task_id (str): Unique UUID tracking this scan request.

    Side Effects:
        - Updates global `RESULTS_CACHE`.
        - Deletes `file_path` from disk upon completion (cleanup).
    """
    try:
        logger.info(f"🔬 Starting scan for task {task_id}")
        result = perform_full_scan(file_path)
        RESULTS_CACHE[task_id] = {"status": "complete", "result": result}
    except Exception as e:
        logger.error(f"Scan failed for {task_id}: {e}")
        RESULTS_CACHE[task_id] = {"status": "error", "detail": str(e)}
    finally:
        # Cleanup temp file
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass

@app.post("/scan", status_code=status.HTTP_202_ACCEPTED, tags=["Scanning"])
async def submit_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    _auth: str = Security(validate_api_key),
):
    """Submits a file for asynchronous scanning.

    The file is saved to a temporary location, and a background task is
    dispatched to process it. The client receives a Task ID immediately.

    Args:
        file (UploadFile): The binary file stream.

    Returns:
        dict: containing the `task_id` and a status message.

    Raises:
        HTTPException (500): If the file cannot be saved to disk.
    """
    task_id = str(uuid.uuid4())
    temp_path = f"/tmp/{task_id}_{file.filename}"

    try:
        # Write to disk so ClamAV/Yara can read it
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        logger.error(f"Disk write failed: {e}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "File save failed")

    # Set initial status
    RESULTS_CACHE[task_id] = {"status": "pending"}

    # Dispatch to background
    background_tasks.add_task(background_scan_task, temp_path, task_id)

    return {
        "task_id": task_id,
        "message": "Scan queued."
    }

@app.get("/results/{task_id}", tags=["Scanning"])
async def get_results(task_id: str, _auth: str = Security(validate_api_key)):
    """Retrieves the status or result of a scan task.

    Args:
        task_id (str): The UUID received from the `/scan` endpoint.

    Returns:
        dict: The task status object. Can be 'pending', 'complete', or 'error'.

    Raises:
        HTTPException (404): If the Task ID is invalid or the result has
            expired from the TTL cache.
    """
    result = RESULTS_CACHE.get(task_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Task not found or expired"
        )
    return result