FROM python:3.13-alpine AS builder

WORKDIR /app

RUN apk add --no-cache build-base libffi-dev openssl-dev

RUN pip install --no-cache-dir poetry poetry-plugin-export

COPY pyproject.toml poetry.lock ./

RUN python -m venv /opt/venv \
    && poetry export -f requirements.txt --only main --without-hashes -o requirements.txt \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt \
    && rm -rf /opt/venv/lib/python3.13/site-packages/pip* \
              /opt/venv/bin/pip*

FROM python:3.13-alpine

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080 \
    PATH="/opt/venv/bin:$PATH"

COPY --from=builder /opt/venv /opt/venv

COPY . .

RUN apk upgrade --no-cache \
    && rm -rf /usr/local/lib/python3.13/site-packages/pip* \
              /usr/local/bin/pip* \
    && addgroup -S appuser \
    && adduser -S appuser -G appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

CMD ["sh", "-c", "gunicorn -b 0.0.0.0:${PORT} app:app"]
