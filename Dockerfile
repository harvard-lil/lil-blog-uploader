FROM python:3.10-slim AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry poetry-plugin-export

COPY pyproject.toml poetry.lock ./

RUN python -m venv /opt/venv \
    && poetry export -f requirements.txt --only main --without-hashes -o requirements.txt \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt \
    && /opt/venv/bin/pip install --no-cache-dir "wheel>=0.46.2" "jaraco.context>=6.1.0" \
    && rm -rf /opt/venv/lib/python3.10/site-packages/pip* \
              /opt/venv/bin/pip*

FROM python:3.10-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    PATH="/opt/venv/bin:$PATH"

COPY --from=builder /opt/venv /opt/venv

COPY . .

RUN rm -rf /usr/local/lib/python3.10/site-packages/pip* \
              /usr/local/bin/pip* \
    && groupadd -r appuser \
    && useradd -r -g appuser appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["sh", "-c", "gunicorn -b 0.0.0.0:${PORT} app:app"]
