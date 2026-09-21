# Spellbook Chia relay — Railway Dockerfile.
# Build context: this directory (set the Railway service "Root Directory" to `relay/`).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# 1. Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. Shared Chia CA (public by design — ships in the open-source
#    chia-blockchain / chia-ssl packages; full nodes verify our client cert
#    against it). We download the wheel only to extract these two files;
#    chia-blockchain itself is NOT installed or needed at runtime.
RUN pip download --no-deps -d /tmp/xch chia-blockchain \
 && python3 - <<'EOF'
import zipfile, glob, os
whl = glob.glob('/tmp/xch/*.whl')[0]
z = zipfile.ZipFile(whl)
os.makedirs('/app/certs', exist_ok=True)
for name in ('chia/ssl/chia_ca.crt', 'chia/ssl/chia_ca.key'):
    with z.open(name) as src, open('/app/certs/' + os.path.basename(name), 'wb') as dst:
        dst.write(src.read())
print('extracted shared Chia CA')
EOF \
 && rm -rf /tmp/xch

# 3. Relay code
COPY . .

# Railway injects $PORT at runtime.
CMD ["python", "server.py"]
