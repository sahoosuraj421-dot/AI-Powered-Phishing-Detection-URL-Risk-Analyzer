# ─── Stage 1: Build / dependency layer ───────────────────────────────────────
FROM python:3.12-slim AS base

# Security: run as non-root user
RUN groupadd -r tripwire && useradd -r -g tripwire tripwire

WORKDIR /app

# Install system dependencies needed by some Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ─── Stage 2: Application ─────────────────────────────────────────────────────
FROM base AS app

WORKDIR /app

# Copy backend source
COPY backend/ ./backend/

# Copy frontend (served as static files)
COPY frontend/ ./frontend/

# Create data directory for SQLite (owned by non-root user)
RUN mkdir -p /data && chown tripwire:tripwire /data

# Use non-root user
USER tripwire

# Set env vars (overridden by docker-compose / K8s secrets)
ENV DATABASE_URL=sqlite:////data/phishing.db \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
