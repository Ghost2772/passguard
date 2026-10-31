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
