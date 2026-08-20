FROM python:3.11-slim AS base

# xray-core is required for tunnel testing; installed from the official
# release rather than pip since it's a Go binary, not a Python package.
ARG XRAY_VERSION=v1.8.24
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl unzip ca-certificates \
    && curl -L -o /tmp/xray.zip \
        "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip" \
    && unzip /tmp/xray.zip -d /usr/local/bin xray \
    && chmod +x /usr/local/bin/xray \
    && rm /tmp/xray.zip \
    && apt-get purge -y curl unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY scripts/ ./scripts/

RUN useradd --create-home --uid 1000 slipgate \
    && mkdir -p /app/data && chown -R slipgate:slipgate /app
USER slipgate

EXPOSE 9090
ENTRYPOINT ["python", "-m", "src.main"]
