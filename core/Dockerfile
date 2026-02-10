# ==============================================================================
# SENTINEL CORE - CONTAINER BUILD INSTRUCTIONS
# ==============================================================================
# This Dockerfile builds the main application gateway.
# It uses a multi-stage build strategy to keep the final image lightweight.
#
# OPTIMIZATION:
# We copy 'requirements.txt' BEFORE the application code. This ensures that
# changes to source code do not invalidate the cached pip install layer.
# ==============================================================================

# 1. Base Image: Python 3.11 Slim (Debian-based, smaller footprint)
FROM python:3.11-slim

# 2. Set Working Directory
WORKDIR /app

# 3. Install System Dependencies
# - gcc: Required to compile certain Python C-extensions.
# - libmagic1: The core library for 'python-magic' (file type detection).
# - rm -rf /var/lib/apt/lists/*: Cleans up apt cache to reduce image size.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# 4. Install Python Dependencies (Cached Layer)
# Copy ONLY requirements.txt first. If this file doesn't change,
# Docker uses the cached result of the pip install command.
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 5. Copy Application Source Code
# This layer changes frequently, so it comes last.
COPY . .

# 6. Runtime Command
# Starts the FastAPI application using Uvicorn.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]