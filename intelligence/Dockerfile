# DARKWATCH Intelligence Service — Production Dockerfile
# Multi-stage build: keeps final image lean and free of build tools

# ── Build stage ──────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build deps (needed for some native packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: run as non-root user
RUN groupadd --gid 1001 darkwatch \
    && useradd --uid 1001 --gid darkwatch --shell /bin/false --no-create-home darkwatch

WORKDIR /app

# Copy only installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY src/ ./src/

# Security hardening
RUN chmod -R 550 /app \
    && chown -R darkwatch:darkwatch /app

USER darkwatch

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Shell form CMD so $PORT variable expands correctly
CMD uvicorn src.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 2 --no-access-log --log-level warning
