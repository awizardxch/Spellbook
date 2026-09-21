# Spellbook Chia relay — Railway Dockerfile.
# Build context: this directory (set the Railway service "Root Directory" to `relay/`).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# 1. Python deps (stdlib + aiohttp + cryptography only).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. Relay code. Includes certs/chia_ca.crt|key — Chia's shared *public* CA
#    (public by design: it ships inside the open-source chia-blockchain
#    package and every Chia install; full nodes verify our client cert
#    against it). cert.py mints a shared-CA-signed node cert from these at
#    startup, and fails closed if they are absent. No build-time network
#    dependency beyond pip.
COPY . .

# Railway injects $PORT at runtime (server.py honors it, default 8000).
CMD ["python", "server.py"]
