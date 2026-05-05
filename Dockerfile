FROM python:3.10-slim

WORKDIR /app

COPY pyproject.toml poetry.lock ./
RUN pip install --no-cache-dir poetry \
    && poetry config virtualenvs.create false \
    && poetry install --no-dev --no-interaction --no-ansi \
    && pip install --no-cache-dir "wheel>=0.46.2" "jaraco.context>=6.1.0"

COPY . .

EXPOSE 8000
CMD gunicorn -b 0.0.0.0:${PORT:-8000} app:app
