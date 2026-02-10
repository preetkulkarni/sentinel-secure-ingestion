"""Global service registry and initialization manager.

This module acts as a singleton container for the application's core logic engines.
It reads from the global `policy` configuration to determine which services
should be instantiated.

Architecture Note:
    - **Core Services** (Crypto, Storage) are mandatory and will always initialize.
    - **Optional Services** (Sanitizer, PII) are conditional based on the `policy` state.
      If a policy disables a service, its global instance remains `None`.
"""

import logging
from app.policy import policy
from engines.crypto_engine import CryptoEngine
from engines.storage_engine import StorageEngine
from engines.sanitizer_engine import SanitizerEngine
from engines.pii_engine import PIIEngine

logger = logging.getLogger("sentinel.services")

# Global Instances
# These are populated by initialize_services() at startup.
# Optional services may remain None if disabled by policy.
crypto_service = None
storage_service = None
sanitizer_service = None
pii_service = None

def initialize_services():
    """Bootstraps the service engines based on the active security policy.

    This function enforces the following startup logic:
    1.  **Mandatory**: Initializes `CryptoEngine` and `StorageEngine`. If these fail,
        the application startup is aborted.
    2.  **Conditional**: Checks `policy.sanitizer_enabled` and `policy.privacy_enabled`.
        If enabled, their respective engines are initialized. If disabled, they are
        logged as skipped and left as `None`.

    Raises:
        Exception: If a mandatory service (Crypto/Storage) fails to initialize.
            Note: Failures in optional services (if enabled) will also raise
            exceptions to prevent "silently broken" security features.
    """
    global crypto_service, storage_service, sanitizer_service, pii_service
    
    try:
        logger.info("⚡ Initializing Global Services...")

        # 1. Core Services (ALWAYS REQUIRED)
        crypto_service = CryptoEngine()
        storage_service = StorageEngine()
        logger.info("✅ Core Engines (Crypto/Storage): Ready")

        # 2. Sanitizer (Conditional)
        if policy.sanitizer_enabled:
            sanitizer_service = SanitizerEngine()
            logger.info("✅ SanitizerEngine: Ready")
        else:
            sanitizer_service = None
            logger.info("⚪ SanitizerEngine: Disabled by Policy")

        # 3. PII Engine (Conditional - Network Dependent)
        if policy.privacy_enabled:
            pii_service = PIIEngine()
            logger.info("✅ PIIEngine: Ready")
        else:
            pii_service = None
            logger.info("⚪ PIIEngine: Disabled by Policy")

    except Exception as e:
        logger.critical(f"❌ Failed to initialize services: {e}")
        raise e