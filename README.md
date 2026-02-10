# 🛡️ Sentinel Platform

**Secure File Ingestion & Data Sanitation Pipeline**

Sentinel is a microservice-based secure ingestion platform designed to sanitize, scan, and encrypt incoming files and data before they reach your internal systems. It acts as a "decontamination airlock" for your infrastructure.

---

## Architecture

The platform consists of two primary microservices and several supporting engines:

1.  **Sentinel Core (`core`)**: The brain of the operation. A FastAPI gateway that handles:
    * **Policy Enforcement**: Validates file types and sizes against `sentinel.yaml`.
    * **Orchestration**: Routes data to the Scanner, PII Engine, and Storage.
    * **Encryption**: Encrypts files using AES-256-GCM (Envelope Encryption).
    * **Storage**: Manages uploads to S3/MinIO.

2.  **Sentinel Scanner (`scanner`)**: The muscle. A dedicated Python service that wraps:
    * **ClamAV**: For signature-based malware detection.
    * **YARA**: For heuristic and custom pattern matching.

3.  **Supporting Services**:
    * **MongoDB**: Stores file metadata, encryption keys (encrypted), and audit logs.
    * **MinIO**: S3-compatible object storage for the encrypted file blobs.
    * **Microsoft Presidio**: (Optional) NLP engines for detecting and redacting PII.



---

## Key Features

* **Zero-Trust File Handling**: Files are scanned by multiple engines (ClamAV + Yara) before acceptance.
* **Envelope Encryption**: Every file gets a unique Data Encryption Key (DEK), which is itself encrypted by a Master Key.
* **Dynamic Policy Engine**: Change security rules (e.g., allow specific MIME types, toggle scanners) via `sentinel.yaml` without redeploying code.
* **PII Scrubbing**: Automatically detects and redacts sensitive data (Credit Cards, SSNs, Emails) from text payloads.
* **XSS Sanitization**: Strips dangerous HTML tags from JSON inputs.

---

## Getting Started

### Prerequisites
* Docker & Docker Compose
* Python 3.11+ (for local SDK usage)

### Quick Start (Docker)

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/preetkulkarni/sentinel-secure-ingestion.git
    cd sentinel-secure-ingestion/deploy
    ```

2.  **Configure Environment**:
    Create a `.env` file in the `deploy/` directory using the `.env.example` file as a guide for environment variables.

3.  **Launch the Stack**:
    ```bash
    docker-compose up --build -d
    ```
---

## Configuration (Policy)

The platform's behavior is controlled by `core/sentinel.yaml`. You can modify this file to tune security settings without touching the code.

```yaml
services:
  scanner: true    # Toggle AV scanning
  privacy: true    # Toggle PII scrubbing

file_security:
  max_size_mb: 50
  allowed_mime_types:
    - application/pdf
    - image/jpeg

privacy:
  pii_entities:
    - CREDIT_CARD
    - EMAIL_ADDRESS
```

#### Note: After changing sentinel.yaml, restart the core service.
---

## API Usage
### 1. Ingest a File (Secure Upload)

```bash
curl -X POST "http://localhost:8000/ingest/file" \
  -F "file=@malware_sample.exe"
```
#### Response (Success):

```JSON
{
  "status": "success",
  "file_id": "65b2f...9a1",
  "message": "File scanned, encrypted, and stored securely."
}
```
#### Response (Blocked):

```JSON
{
  "detail": "Security Validation Failed: ClamAV: Win.Test.EICAR_HDB-1 FOUND"
}
```

### 2. Ingest Data (Sanitize & Scrub)

```bash
curl -X POST "http://localhost:8000/ingest/data" \
  -H "Content-Type: application/json" \
  -d '{
    "collection": "user_comments",
    "payload": {
      "username": "alicex",
      "comment": "Call me at 555-0199 or <script>alert(1)</script>"
    },
    "sanitize_fields": ["comment"],
    "scrub_pii": true
  }'
```

#### Response:

```JSON
{
  "preview": {
    "username": "alicex",
    "comment": "Call me at [REDACTED-PHONE] or &lt;script&gt;alert(1)&lt;/script&gt;"
  }
}
```
---

## Python Client SDK
A dedicated SDK is available in `sdk/` to simplify integration.

```python
from sentinel.client import SentinelClient

client = SentinelClient(base_url="http://localhost:8000")

# 1. Upload a file
try:
    response = client.ingest_file("contract.pdf")
    print(f"Uploaded! File ID: {response['file_id']}")
except Exception as e:
    print(f"Upload blocked: {e}")

# 2. Download (Decrypts automatically)
client.retrieve_file(response['file_id'], output_path="downloaded_contract.pdf")
```
---

## Project Structure

```Plaintext
sentinel-secure-ingestion/

.
├── README.md
├── core
│   ├── Dockerfile
│   ├── app
│   │   ├── config.py
│   │   ├── dbconnect.py
│   │   ├── main.py
│   │   └── policy.py
│   ├── engines
│   │   ├── crypto_engine.py
│   │   ├── instances.py
│   │   ├── pii_engine.py
│   │   ├── sanitizer_engine.py
│   │   ├── scanner_bridge.py
│   │   └── storage_engine.py
│   └── requirements.txt
├── deploy
│   ├── docker-compose.yml
│   └── sentinel.yaml
├── scanner
│   ├── Dockerfile
│   ├── app.py
│   ├── config.py
│   ├── requirements.txt
│   └── scanner.py
└── sdk
    ├── sentinel
    │   ├── __init__.py
    │   └── client.py
    └── setup.py
```
---