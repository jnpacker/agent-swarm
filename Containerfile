FROM registry.access.redhat.com/ubi9/python-312-minimal:latest

WORKDIR /app

# Install dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY swarmer/ swarmer/

# Directories for mounted volumes (PVC for DB, Secret for auth hash)
# Switch to root to create dirs, then back to 1001 for runtime
USER 0
RUN mkdir -p /data /auth && \
    chgrp -R 0 /data /auth && \
    chmod -R g+rwX /data /auth
USER 1001

ENV PYTHONUNBUFFERED=1 \
    K8S_IN_CLUSTER=true \
    AUTH_HASH_FILE=/auth/password.hash \
    DATABASE_URL=sqlite+aiosqlite:////data/swarmer.db

EXPOSE 8080

CMD ["uvicorn", "swarmer.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips=*"]
