FROM python:3.11-slim-bookworm

# Install System Dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Application Code
COPY app/ /app/app/

# Create directories for data
RUN mkdir -p /app/data
RUN mkdir -p /app/data/triggers

# Create repos directory outside of /app to avoid volume mount overwrite
RUN mkdir -p /opt/repos

# Clone Sigma rules repository for offline use
RUN git clone --depth 1 https://github.com/SigmaHQ/sigma.git /opt/repos/sigma || echo "Sigma repo clone failed"

# Clone pySigma pipelines for better MITRE mappings
RUN git clone --depth 1 https://github.com/SigmaHQ/pySigma-pipeline-windows.git /opt/repos/pysigma-windows || echo "pySigma Windows pipeline clone failed"
RUN git clone --depth 1 https://github.com/SigmaHQ/pySigma-pipeline-sysmon.git /opt/repos/pysigma-sysmon || echo "pySigma Sysmon pipeline clone failed"

# Download MITRE ATT&CK data for offline use
RUN mkdir -p /opt/repos/mitre && \
    curl -sSL -o /opt/repos/mitre/enterprise-attack.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json || true && \
    curl -sSL -o /opt/repos/mitre/mobile-attack.json https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json || true && \
    curl -sSL -o /opt/repos/mitre/ics-attack.json https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json || true && \
    curl -sSL -o /opt/repos/mitre/pre-attack.json https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json || true

# Environment setup
ENV PYTHONPATH="/app/app"
ENV PYTHONUNBUFFERED=1
ENV SIGMA_REPO_PATH=/opt/repos/sigma
ENV MITRE_REPO_PATH=/opt/repos/mitre
