# TIDE FastAPI - Production Dockerfile
# base -> builder -> production -> development

# Stage 1: Base
FROM python:3.11-slim-bookworm AS base
WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Stage 2: Builder
FROM base AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl git && \
    rm -rf /var/lib/apt/lists/*

# Create a Virtual Environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 3: Production
FROM base AS production
# Copy the entire Virtual Environment
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# System deps needed for runtime (curl for healthcheck, git for sigma)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app/data /app/logs /opt/repos/mitre /opt/repos/sigma

# Clone Repos (Note: These stay in the image layer)
RUN git clone --depth 1 https://github.com/SigmaHQ/sigma.git /opt/repos/sigma
RUN curl -sSL -o /opt/repos/mitre/enterprise-attack.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json && \
    curl -sSL -o /opt/repos/mitre/mobile-attack.json https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json && \
    curl -sSL -o /opt/repos/mitre/ics-attack.json https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json && \
    curl -sSL -o /opt/repos/mitre/pre-attack.json https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json

# Create non-root user FIRST
RUN useradd -m -u 1000 tide

COPY app/ /app/app/

ENV PYTHONPATH="/app"

# CRUCIAL: Set ownership AFTER all files are in place, BEFORE switching user
RUN chown -R 1000:1000 /app/data /app/logs /opt/repos /app/app

# Switch to non-root user LAST
USER tide

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Stage 4: Development
FROM production AS development
USER root
# We are already in the venv, so this installs into /opt/venv
RUN pip install --no-cache-dir watchfiles 
USER tide
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]