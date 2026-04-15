# Multi-stage build: compile dependencies in builder, copy to minimal runtime image
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and pre-compile wheels
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Runtime stage: minimal production image
FROM python:3.11-slim

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /home/appuser/.local

# Create non-root user
RUN useradd -m -u 1000 appuser && \
    mkdir -p logs users && \
    chown -R appuser:appuser /app

# Set environment for pip packages
ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER appuser

# Copy application files
COPY --chown=appuser:appuser . .

# Expose port for the server
EXPOSE 9000

# Healthcheck: verify server is listening on port 9000
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import socket; s = socket.socket(); s.connect(('localhost', 9000)); s.close()" || exit 1

# Default command: start the server
CMD ["python", "server.py"]
