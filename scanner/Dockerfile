# ==============================================================================
# SENTINEL SCANNER - CONTAINER BUILD INSTRUCTIONS
# ==============================================================================
# This Dockerfile builds the specialized AV microservice.
# It includes the build tools necessary for compiling YARA rules and
# fetches the latest open-source malware signatures during the build.
# ==============================================================================

# 1. Base Image
FROM python:3.11-slim

# 2. Install Build Dependencies
# - git: To clone the signature repository.
# - libyara-dev: Headers required for the 'yara-python' library.
# - build-essential: Compiler toolchain for building YARA.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    libyara-dev \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

# 3. Fetch YARA Signatures
# We clone 'Neo23x0/signature-base', a high-quality open-source ruleset.
# This happens at build time so the container starts up quickly.
RUN git clone https://github.com/Neo23x0/signature-base.git /app/signature-base

# 4. Set Working Directory
WORKDIR /app

# 5. Install Python Dependencies (Cached Layer)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 6. Copy Scanner Source Code
COPY . .

# 7. Runtime Command
# Starts the Scanner API on port 5000 (distinct from Core's 8000).
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]