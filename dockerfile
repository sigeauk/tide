# Stage 1: Base
FROM python:3.14.3-slim-bookworm AS base
WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Stage 2: Builder
FROM base AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    nano \
    jq\
    && rm -rf /var/lib/apt/lists/*

# Create a Virtual Environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Stage 3: Production
FROM base AS production
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# System deps needed for runtime:
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    nano \
    jq \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app/data /app/logs /opt/repos/mitre /opt/repos/sigma

# ─── DATA REPOS ───────────────────
RUN git clone --depth 1 https://github.com/SigmaHQ/sigma.git /opt/repos/sigma
RUN curl -sSL -o /opt/repos/mitre/enterprise-attack.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json && \
    curl -sSL -o /opt/repos/mitre/mobile-attack.json https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json && \
    curl -sSL -o /opt/repos/mitre/ics-attack.json https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json && \
    curl -sSL -o /opt/repos/mitre/pre-attack.json https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json

# Copy application code and VERSION file
COPY app/ /app/app/
COPY VERSION /app/VERSION

ENV PYTHONPATH="/app"

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Stage 4: Development
FROM production AS development
RUN pip install --no-cache-dir watchfiles
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]