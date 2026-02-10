"""Cryptographic operations for the Sentinel platform.

This module implements 'Envelope Encryption' using AES-256-GCM.
Instead of using a single key for all files, we generate a unique Data Encryption Key (DEK)
for every file, and then encrypt that DEK using the Master Key.

Security Model:
    - Master Key (KEK): Stored in env vars / Secret Manager.
    - Data Key (DEK): Generated per file, stored encrypted in DB alongside metadata.
    - Algorithm: AES-GCM (provides both confidentiality and integrity).
"""

import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from app.config import settings

logger = logging.getLogger("sentinel.crypto")

class CryptoEngine:
    """Handles the encryption and decryption lifecycle for files."""

    def __init__(self):
        """Initializes the Crypto Engine with the Master Key.

        Strictly requires `SENTINEL_MASTER_KEY` to be present in the configuration.

        Raises:
            ValueError: If the Master Key is missing, not a valid hex string,
                or has an incorrect length (must be 32 bytes/256 bits).
        """
        # 1. Load Master Key
        env_key = settings.SENTINEL_MASTER_KEY.get_secret_value()
        
        if not env_key:
            logger.critical("⛔ SENTINEL_MASTER_KEY is missing. Cannot start.")
            raise ValueError("Configuration Error: Master Key is required.")

        try:
            self.master_key = bytes.fromhex(env_key)
            if len(self.master_key) != 32: # 256 bits
                raise ValueError(f"Key length must be 32 bytes (got {len(self.master_key)})")
                
            logger.info("🔐 Crypto Engine Initialized (256-bit AES-GCM)")
            
        except ValueError as e:
            logger.critical(f"⛔ Invalid Master Key format: {e}")
            raise ValueError("SENTINEL_MASTER_KEY must be a valid 64-character hex string.")

        # Initialize the Master Cipher
        self.aesgcm = AESGCM(self.master_key)

    def encrypt_file(self, file_data: bytes) -> dict:
        """Encrypts file content using the Envelope Encryption pattern.

        1. Generates a random, ephemeral 256-bit Data Encryption Key (DEK).
        2. Encrypts the `file_data` using this DEK.
        3. Encrypts the DEK using the persistent Master Key.

        Args:
            file_data (bytes): The raw file content to encrypt.

        Returns:
            dict: A dictionary containing all artifacts needed for storage/decryption:
                {
                    "data": bytes,          # The encrypted file content
                    "file_iv": str (hex),   # IV used for the file encryption
                    "dek_encrypted": str (hex), # The DEK encrypted by Master Key
                    "dek_iv": str (hex)     # IV used for the DEK encryption
                }

        Raises:
            RuntimeError: If the encryption process fails unexpectedly.
        """
        try:
            # A. Generate ephemeral DEK (256-bit) & Nonces
            dek = AESGCM.generate_key(bit_length=256)
            dek_iv = os.urandom(12)  # NIST recommended nonce size
            file_iv = os.urandom(12)

            # B. Encrypt the file content
            file_aes = AESGCM(dek)
            encrypted_data = file_aes.encrypt(file_iv, file_data, None)

            # C. Wrap the DEK (Envelope)
            encrypted_dek = self.aesgcm.encrypt(dek_iv, dek, None)

            # Cleanup sensitive temp variables (Best effort in Python)
            del dek
            del file_aes

            return {
                "data": encrypted_data,      # bytes
                "file_iv": file_iv.hex(),    # str
                "dek_encrypted": encrypted_dek.hex(), # str
                "dek_iv": dek_iv.hex(),      # str
            }
        except Exception as e:
            logger.error(f"Encryption failure: {e}")
            raise RuntimeError("Encryption process failed.")

    def decrypt_file(self, bundle: dict) -> bytes:
        """Decrypts a file by unwrapping the DEK and then the content.

        Args:
            bundle (dict): A dictionary containing:
                - "data": Encrypted file bytes
                - "dek_iv": Hex string of the DEK's IV
                - "dek_encrypted": Hex string of the encrypted DEK
                - "file_iv": Hex string of the file's IV

        Returns:
            bytes: The original, decrypted file content.

        Raises:
            ValueError: If decryption fails due to data corruption,
                tampering (Integrity Check), or incorrect keys.
        """
        try:
            # 1. Decode metadata
            dek_iv = bytes.fromhex(bundle["dek_iv"])
            dek_encrypted = bytes.fromhex(bundle["dek_encrypted"])
            file_iv = bytes.fromhex(bundle["file_iv"])

            # 2. Unwrap DEK
            # This will raise InvalidTag if the Master Key is wrong or data corrupted
            dek = self.aesgcm.decrypt(dek_iv, dek_encrypted, None)

            # 3. Decrypt Content
            file_aes = AESGCM(dek)
            original_data = file_aes.decrypt(file_iv, bundle["data"], None)

            del dek
            del file_aes
            
            return original_data

        except InvalidTag:
            logger.warning("Decryption failed: Invalid Tag (Wrong Key or Corrupted Data)")
            raise ValueError("Decryption failed. Integrity check failed.")
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise ValueError("Decryption process failed.")