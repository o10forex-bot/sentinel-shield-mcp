FROM python:3.10-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

COPY requirements.txt pyproject.toml README.md mcp.json /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel_shield /app/sentinel_shield
COPY tests /app/tests
RUN pip install --no-cache-dir -e . && pytest -v

EXPOSE 8000

CMD ["sh", "-c", "uvicorn sentinel_shield.remote_server:app --host 0.0.0.0 --port ${PORT:-8000}"]
