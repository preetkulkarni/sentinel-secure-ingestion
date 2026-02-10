"""Multi-engine security scanner wrapper.

This module aggregates detection logic from two distinct engines:
1.  **ClamAV**: An open-source antivirus engine accessed via TCP (network socket).
    It is effective against known malware signatures (trojans, worms, etc.).
2.  **YARA**: A pattern matching swiss-army knife. It is effective for identifying
    specific byte patterns, strings, or custom rules defined by the organization.
"""

import clamd
import logging
import os
import yara
from config import avsettings

logger = logging.getLogger("sentinel.engine")

# Global Rules Holder
YARA_RULES = None

def compile_yara_rules():
    """Compiles all YARA signatures found in the configured rules directory.

    This function iterates through the `YARA_RULES_PATH`, collects all `.yar` and
    `.yara` files, and compiles them into a single binary object for efficient matching.

    Supported Externals:
        The following external variables are available to YARA rules:
        - filename (string)
        - filepath (string)
        - extension (string)
        - filetype (string)
        - owner (string)

    Global Side Effects:
        Sets the global `YARA_RULES` variable.
    """
    global YARA_RULES
    rules_path = avsettings.YARA_RULES_PATH
    
    logger.info(f"📁 Loading YARA rules from: {rules_path}")

    if not os.path.isdir(rules_path):
        logger.error(f"❌ YARA directory not found: {rules_path}")
        return

    rule_files = {}
    for root, _, files in os.walk(rules_path):
        for filename in files:
            if filename.endswith((".yar", ".yara")):
                filepath = os.path.join(root, filename)
                rule_files[filename] = filepath

    if not rule_files:
        logger.warning("⚠️ No YARA rules found. YARA scanning will be skipped.")
        return

    try:
        # Compile all rules into one object for performance
        YARA_RULES = yara.compile(
            filepaths=rule_files,
            externals={
                    "filename": "string",
                    "filepath": "string",
                    "extension": "string",
                    "filetype": "string",
                    "owner": "string"
                }
            )
        logger.info(f"✅ Compiled {len(rule_files)} YARA rule sets.")
    except yara.Error as e:
        logger.critical(f"❌ YARA Compilation Failed: {e}")
        # In strict production, you might want to raise e and crash here.

def scan_file_clamav(file_path: str) -> dict:
    """Streams a file to the ClamAV daemon for malware scanning.

    This function uses a TCP socket to stream the file data directly to the
    ClamAV container (`clamd`). This is more memory-efficient than loading
    the entire file into RAM before sending.

    Args:
        file_path (str): The local path to the file to be scanned.

    Returns:
        dict: A dictionary containing the scan verdict:
            - status (str): "clean", "infected", or "error".
            - details (str): The name of the malware found or error message.
    """
    try:
        # 1. Connect to the ClamAV Container
        cd = clamd.ClamdNetworkSocket(
            avsettings.CLAMAV_HOST, 
            avsettings.CLAMAV_PORT
        )
        
        # 2. Check if ClamAV is ready (it takes time to load DB)
        try:
            cd.ping()
        except Exception:
            return {"status": "error", "details": "ClamAV Engine is warming up"}

        # 3. Stream the file (Efficient - doesn't load whole file into RAM)
        # We open the file and send its bytes
        with open(file_path, "rb") as f:
            # instream() sends data and returns result like: {'stream': ('FOUND', 'Win.Test.EICAR')}
            scan_result = cd.instream(f)

        response = scan_result.get('stream')
        status_code, virus_name = response

        if status_code == 'OK':
            return {"status": "clean", "details": "No threats found"}
        elif status_code == 'FOUND':
            return {"status": "infected", "details": virus_name}
        else:
            return {"status": "error", "details": f"Unknown response: {response}"}

    except FileNotFoundError:
        return {"status": "error", "details": "File not found for scanning"}
    except Exception as e:
        logger.error(f"ClamAV Network Scan Error: {e}")
        return {"status": "error", "details": "ClamAV connection failed"}

def scan_file_yara(file_path: str) -> dict:
    """Matches the file against the compiled YARA ruleset.

    Args:
        file_path (str): The local path to the file to be scanned.

    Returns:
        dict: A dictionary containing the match results:
            - matches (list): A list of rule names that triggered.
    """
    if YARA_RULES is None:
        return {"matches": []} # Fail open or closed? Here we fail open (clean).

    try:
        matches = YARA_RULES.match(filepath=file_path)
        match_names = [m.rule for m in matches]
        return {"matches": match_names}
    except Exception as e:
        logger.error(f"YARA Scan error: {e}")
        return {"matches": ["error_scanning"]}

def perform_full_scan(file_path: str) -> dict:
    """Executes both ClamAV and YARA scans sequentially.

    Args:
        file_path (str): The local path to the file.

    Returns:
        dict: A combined result dictionary with keys 'clamav' and 'yara'.
    """
    return {
        "clamav": scan_file_clamav(file_path),
        "yara": scan_file_yara(file_path)
    }