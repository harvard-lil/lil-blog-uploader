# Pinned tool images. uv is used only to install the locked dependencies and
# is not left in the runtime image.
FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv
FROM python:3.14-slim-trixie@sha256:35caba83af2fe6da9a5d922f9b0156f21d1246a48278c58a08bd253303ba42e8

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_DOWNLOADS=never \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# The locked runtime dependencies, from the manifest and lockfile alone so this
# layer is independent of app-code changes. pip is removed afterwards: nothing
# at runtime installs packages, and scanners report its advisories otherwise.
RUN --mount=from=uv,source=/uv,target=/bin/uv \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    uv sync --locked --no-dev --no-cache \
    && rm -rf /usr/local/lib/python3.14/site-packages/pip* /usr/local/bin/pip*

RUN useradd -r appuser

COPY app.py error_handling.py ./
COPY static ./static
COPY templates ./templates

USER appuser

EXPOSE 8000

# --no-control-socket: gunicorn 25.1+ otherwise opens a runtime-management
# socket under $HOME, which this service does not use.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--no-control-socket", "app:app"]
