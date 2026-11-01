FROM ghcr.io/gitleaks/gitleaks:v8.30.1 AS gitleaks

FROM node:24-alpine AS panel
WORKDIR /panel
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend ./
RUN npm run build

FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/workspace/src:/workspace
WORKDIR /workspace
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
COPY scripts ./scripts
COPY infra ./infra

FROM base AS tools
CMD ["python", "-m", "scripts.bootstrap"]

FROM base AS demo
USER 10001:10001
EXPOSE 8001
CMD ["python", "-m", "uvicorn", "passguard.main:app", "--host", "0.0.0.0", "--port", "8001", "--no-server-header"]

FROM base AS control
COPY --from=panel /panel/dist /workspace/panel
USER 10002:10002
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "passguard.control.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]

FROM base AS scanner
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
USER 10003:10003
EXPOSE 8002
CMD ["python", "-m", "uvicorn", "passguard.scanner.service:app", "--host", "0.0.0.0", "--port", "8002", "--no-server-header", "--no-access-log"]
