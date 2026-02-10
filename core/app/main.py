"""Main application entry point for the Sentinel Core service.

This module initializes the FastAPI application, configures middleware,
and defines the primary API endpoints. It integrates with the `policy` module
to enforce dynamic security constraints and feature toggles.
"""

import asyncio
import uuid
import logging
import magic
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, File, HTTPException, UploadFile, status, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from bson import ObjectId

# Local imports
from app.config import settings
from app.config import DataPayload
from app.policy import policy
from app.dbconnect import close_mongo_connection, connect_to_mongo, get_database
from engines.scanner_bridge import scan_file
import engines.instances as services

# Setup Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel.api")

def validate_magic_bytes(file_content: bytes) -> str:
    """Validates the file content against the policy allowlist.

    Uses `python-magic` to inspect the file header bytes (magic numbers) 
    to determine the true MIME type, ignoring the user-provided extension.

    Args:
        file_content (bytes): The raw file content.

    Returns:
        str: The detected MIME type if it is allowed by `policy.allowed_mime_types`.

    Raises:
        HTTPException (415): If the detected type is not in the policy allowlist.
    """
    # 1. Detect MIME from bytes (e.g., 'application/pdf')
    detected_mime = magic.from_buffer(file_content, mime=True)
    
    # 2. Check against Allowlist
    if detected_mime not in policy.allowed_mime_types:
        logger.warning(f"⛔ Blocked file type: {detected_mime}")
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Unsupported file type: {detected_mime}. Allowed: {policy.allowed_mime_types}"
        )
    
    return detected_mime

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages application lifecycle resources.

    - **Startup**: Initializes global service instances (crypto, storage) and 
      database connections.
    - **Shutdown**: Closes HTTP clients and database pools.
    """
    # 1. Startup
    logger.info("🚀 Sentinel Core starting up...")
    # Initialize Engines
    services.initialize_services()
    app.state.http_client = httpx.AsyncClient(timeout=30.0) # Increased timeout for scans
    await connect_to_mongo()
    
    yield
    
    # 2. Shutdown
    logger.info("🛑 Sentinel Core shutting down...")
    await app.state.http_client.aclose()
    await close_mongo_connection()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware (Crucial for Frontend integration)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In strict production, replace "*" with specific domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    """Returns the operational status of the service."""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc)}

@app.post("/ingest/file")
async def ingest_file(request: Request, file: UploadFile = File(...)):
    """Executes the Secure File Ingestion Pipeline.

    This endpoint enforces policies defined in `app.policy`.
    
    Pipeline Steps:
    1. **Size Check**: Validates file size against `policy.max_file_size_bytes`.
    2. **Type Check**: Validates magic bytes against `policy.allowed_mime_types`.
    3. **Scan**: (Conditional) Scans for malware if `policy.scanner_enabled` is True.
    4. **Encrypt**: Encrypts file content (CPU-bound).
    5. **Upload**: Persists encrypted blob to storage (IO-bound).
    6. **Index**: Saves metadata to MongoDB.

    Args:
        request (Request): The raw request (for app state access).
        file (UploadFile): The file stream.

    Returns:
        dict: A success message with the new file ID.
    """
    logger.info(f"📥 Receiving file: {file.filename}")

    try:
        # 1. Read Bytes & Validate Size
        # Warning: .read() loads into RAM. 
        # For >100MB files, we must refactor to use a Streaming Pipeline.
        file_content = await file.read()
        file_size = len(file_content)

        if file_size > policy.max_file_size_bytes:
            logger.warning(f"⚠️ File rejected (Size: {file_size} bytes)")
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large. Maximum limit is {policy.max_file_size_bytes // (1024*1024)}MB."
            )

        validated_mime = validate_magic_bytes(file_content)
        logger.info(f"✅ File type verified: {validated_mime}")

        # 2. AV Scan (Async)
        # We pass the client from app.state
        if policy.scanner_enabled:
            logger.info(f"🔍 Scanning {file.filename}...")
            await scan_file(request.app.state.http_client, file_content, file.filename)
            logger.info("✅ Scan Clean")
        else:
            logger.info("⏩ Skipping AV Scan (Disabled in Policy)")

        # 3. Encrypt (CPU Bound -> Thread)
        encrypted_package = await asyncio.to_thread(
            services.crypto_service.encrypt_file, file_content
        )

        # 4. Upload to Object Storage (IO Bound -> Thread)
        storage_filename = f"{uuid.uuid4()}-{file.filename}"
        
        metadata = {
            "original_name": file.filename,
            "uploaded_at": datetime.now(timezone.utc).isoformat(),
            "size_bytes": str(file_size),
            "validated_mime": validated_mime
        }

        logger.info("☁️ Uploading to storage...")
        storage_path = await asyncio.to_thread(
            services.storage_service.upload, 
            file_name=storage_filename,
            data=encrypted_package["data"],
            content_type=validated_mime, 
            metadata=metadata,
        )

        # 5. Save Metadata to MongoDB
        file_doc = {
            "filename": file.filename,
            "storage_key": storage_filename,
            "content_type": validated_mime,
            "size": file_size,
            "storage_path": storage_path,
            "encryption": {
                "dek_encrypted": encrypted_package["dek_encrypted"],
                "dek_iv": encrypted_package["dek_iv"],
                "file_iv": encrypted_package["file_iv"],
            },
            "status": "secure",
            "ingested_at": datetime.now(timezone.utc),
        }

        database = await get_database()
        new_file = await database["files"].insert_one(file_doc)

        logger.info(f"🎉 Success. File ID: {new_file.inserted_id}")

        return {
            "status": "success",
            "file_id": str(new_file.inserted_id),
            "message": "File scanned, encrypted, and stored securely.",
        }

    except HTTPException as he:
        # Re-raise HTTP exceptions (like 400 from scanner or 413 size limit)
        raise he
    except ValueError as ve:
        # Security check failures from engines
        logger.warning(f"⛔ Security validation failed: {ve}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Security check failed: {str(ve)}",
        )
    except Exception as e:
        # Catch unexpected server errors
        logger.error(f"❌ Internal Ingestion Error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal processing failed.",
        )
    
@app.post("/ingest/data")
async def ingest_data(request: DataPayload):
    """Executes the Secure Data Ingestion Pipeline.

    Enforces conditional logic based on `policy`:
    1. **Sanitization**: Performed only if `policy.sanitizer_enabled` AND requested.
    2. **PII Scrubbing**: Performed only if `policy.privacy_enabled` AND requested.

    Args:
        request (DataPayload): The data packet containing the payload and options.

    Returns:
        dict: Success message with document ID and data preview.
    """
    data = request.payload

    # 1. Sanitize HTML (CONDITIONAL)
    # Check both the Policy AND the Request
    if policy.sanitizer_enabled and request.sanitize_fields:
        # We must assume sanitizer_service is not None because we checked policy
        data = services.sanitizer_service.clean_payload(data, request.sanitize_fields)
    
    # 2. Scrub PII (CONDITIONAL)
    if policy.privacy_enabled and request.scrub_pii:
        for key, val in data.items():
            if isinstance(val, str):
                data[key] = await services.pii_service.scrub(val)

    # 3. Store in MongoDB
    database = await get_database()
    
    if request.collection.startswith("system") or request.collection.startswith("admin"):
         raise HTTPException(status_code=400, detail="Invalid collection name")

    # The insert_one method adds "_id" to 'data' in-place!
    result = await database[request.collection].insert_one(data)

    data.pop("_id", None) 

    return {
        "status": "success",
        "doc_id": str(result.inserted_id),
        "message": "Data processed and stored securely",
        "preview": data 
    }

@app.get("/retrieve/file/{file_id}")
async def retrieve_file(file_id: str):
    """Retrieves and decrypts a file from storage.

    Steps:
    1. **Lookup**: Validates file ID and fetches metadata from MongoDB.
    2. **Fetch**: Downloads encrypted blob from Object Storage (Async).
    3. **Decrypt**: Restores original content using stored keys (Async/Threaded).
    
    Args:
        file_id (str): The MongoDB ObjectId for the file.

    Returns:
        Response: The file content as a downloadable stream.
    """
    database = await get_database()
    
    # 1. Find File Metadata
    try:
        oid = ObjectId(file_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid File ID format")
        
    file_doc = await database["files"].find_one({"_id": oid})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File metadata not found")

    # 2. Get Encrypted Bytes from Storage
    # The 'storage_path' in DB is now just the Key (e.g. "uuid-filename.pdf")
    # If your DB still has "bucket/filename", we handle it:
    storage_key = file_doc["storage_path"].split("/")[-1]
    
    try:
        encrypted_bytes = await asyncio.to_thread(
            services.storage_service.get_file, storage_key  # noqa: F821
        )
    except FileNotFoundError:
        logger.error(f"Consistency Error: File {file_id} exists in DB but not in S3.")
        raise HTTPException(status_code=404, detail="File blob missing from storage")
    except Exception as e:
        logger.error(f"Storage retrieval failed: {e}")
        raise HTTPException(status_code=500, detail="Storage retrieval failed")

    # 3. Construct the Bundle for Decryption
    decryption_bundle = {
        "data": encrypted_bytes,
        "dek_iv": file_doc["encryption"]["dek_iv"],
        "dek_encrypted": file_doc["encryption"]["dek_encrypted"],
        "file_iv": file_doc["encryption"]["file_iv"]
    }

    # 4. Decrypt (CPU Bound - Move to Thread)
    try:
        clean_bytes = await asyncio.to_thread(
            services.crypto_service.decrypt_file, decryption_bundle # noqa: F821
        )
    except ValueError:
        logger.critical(f"Integrity Error: Decryption failed for {file_id}")
        raise HTTPException(status_code=500, detail="Decryption failed (Integrity Check)")

    # 5. Return as File Download
    # Note: For files <50MB, returning bytes directly is fine.
    # For larger files, we would need a chunked decryption generator (StreamingResponse).
    return Response(
        content=clean_bytes,
        media_type=file_doc.get("content_type", "application/octet-stream"),
        headers={
            "Content-Disposition": f'attachment; filename="{file_doc["filename"]}"'
        }
    )
