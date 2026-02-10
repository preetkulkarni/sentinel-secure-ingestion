"""Object storage management for the Sentinel platform.

This module handles interactions with S3-compatible storage services (like AWS S3 or MinIO).
It manages the lifecycle of storage buckets and provides high-level abstractions for
uploading and retrieving encrypted file blobs.
"""

import boto3
import logging
from botocore.exceptions import ClientError
from app.config import settings

# Setup Logger
logger = logging.getLogger("sentinel.storage")

class StorageEngine:
    """A wrapper for the Boto3 S3 client handling file persistence."""

    def __init__(self):
        """Initializes the S3 client and validates bucket availability.

        It attempts to connect to the configured S3 endpoint and ensures the
        target bucket exists.

        Raises:
            Exception: If the connection to the storage backend fails during initialization.
        """
        try:
            self.s3 = boto3.client(
                "s3",
                endpoint_url=settings.S3_ENDPOINT.get_secret_value(),
                aws_access_key_id=settings.S3_ACCESS_KEY.get_secret_value(), 
                aws_secret_access_key=settings.S3_SECRET_KEY.get_secret_value(),
                region_name="us-east-1",  # Required dummy region for MinIO
            )
            
            logger.info("☁️ Storage Engine connecting...")
            self._ensure_buckets()
            
        except Exception as e:
            logger.critical(f"⛔ Failed to initialize Storage Engine: {e}")
            raise e

    def _ensure_buckets(self):
        """Verifies that the required storage bucket exists, creating it if necessary.

        This method performs a `head_bucket` check. If the bucket is missing (404),
        it attempts to create it.

        Raises:
            ClientError: If access is forbidden (403) or other AWS/MinIO errors occur.
        """
        bucket_name = settings.S3_BUCKET_CLEAN
        try:
            self.s3.head_bucket(Bucket=bucket_name)
            logger.info(f"✅ Bucket found: {bucket_name}")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            # 404 Not Found means we can create it
            if error_code == "404":
                try:
                    self.s3.create_bucket(Bucket=bucket_name)
                    logger.info(f"✨ Bucket created: {bucket_name}")
                except Exception as create_error:
                    logger.critical(f"⛔ Failed to create bucket {bucket_name}: {create_error}")
                    raise create_error
            else:
                # 403 Forbidden or other connection errors
                logger.critical(f"⛔ S3 Connection Error ({error_code}): {e}")
                raise e

    def upload(self, file_name: str, data: bytes, content_type: str, metadata: dict) -> str:
        """Uploads a file object to the storage bucket.

        Args:
            file_name (str): The unique key (filename) for the object in S3.
            data (bytes): The binary content of the file.
            content_type (str): The MIME type of the file (e.g., 'application/pdf').
            metadata (dict): Custom metadata key-value pairs to attach to the object.
                Note: All values in this dict are strictly converted to strings to
                satisfy AWS S3 requirements.

        Returns:
            str: The S3 Key (file_name) of the uploaded object.

        Raises:
            RuntimeError: If the upload operation fails.
        """
        # S3 Metadata MUST be strings. Boto3 will error on Integers.
        safe_metadata = {k: str(v) for k, v in metadata.items()}

        try:
            self.s3.put_object(
                Bucket=settings.S3_BUCKET_CLEAN,
                Key=file_name,
                Body=data,
                ContentType=content_type,
                Metadata=safe_metadata,
            )
            return file_name
            
        except Exception as e:
            logger.error(f"❌ Upload failed for {file_name}: {e}")
            raise RuntimeError("Storage upload failed")

    def get_file(self, file_path: str) -> bytes:
        """Retrieves a file object from storage.

        Args:
            file_path (str): The S3 Key of the file to retrieve.

        Returns:
            bytes: The raw binary content of the file.

        Raises:
            FileNotFoundError: If the specified key does not exist in the bucket.
            ClientError: If there are permission issues or connection failures.
        """
        try:
            response = self.s3.get_object(Bucket=settings.S3_BUCKET_CLEAN, Key=file_path)
            return response['Body'].read()
        except ClientError as e:
            if e.response['Error']['Code'] == "NoSuchKey":
                logger.warning(f"File not found in S3: {file_path}")
                raise FileNotFoundError("File missing from storage")
            else:
                logger.error(f"S3 Download Error: {e}")
                raise e
        except Exception as e:
            logger.error(f"Unexpected S3 Error: {e}")
            raise e