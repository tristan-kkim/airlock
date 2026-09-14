# syntax=docker/dockerfile:1.7
#
# Airlock public demo image. Two runtime targets:
#
#   demo     (default) FastAPI only, detector backend `cloud` (Token Factory Nemotron-3-Nano-30B-A3B).
#            Small; fits a 1 GB instance.
#   sidecar  FastAPI + llama.cpp `llama-server` with Nemotron-3-Nano-4B in the same container
#            (detector backend `local`). Needs about 4 GB RAM; the GGUF is downloaded at start.
#
# Build for Nebius / most hosts (x86_64):  docker buildx build --platform linux/amd64 -t airlock-demo .
# Nothing secret is baked in: NEBIUS_API_KEY and TAVILY_API_KEY come from the platform at runtime.

ARG PYTHON_IMAGE=python:3.12-slim-trixie
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.9.28
ARG LLAMA_IMAGE=ghcr.io/ggml-org/llama.cpp:server

FROM ${UV_IMAGE} AS uv

# ---------------------------------------------------------------- build: locked deps, no dev, no GLiNER
FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project
COPY README.md LICENSE ./
COPY airlock ./airlock
# --reinstall-package: uv reuses a cached wheel of a local project unless pyproject.toml changed,
# which would silently ship stale code from the cache mount.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --reinstall-package airlock

# ---------------------------------------------------------------- demo (default target is last)
FROM ${PYTHON_IMAGE} AS demo-base
RUN groupadd --system --gid 10001 airlock \
    && useradd --system --uid 10001 --gid airlock --home-dir /home/airlock --create-home airlock
COPY --from=build --chown=root:root /app/.venv /app/.venv
COPY --chown=root:root LICENSE /app/LICENSE
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AIRLOCK_DEMO=1 \
    AIRLOCK_HOST=0.0.0.0 \
    AIRLOCK_PORT=8801 \
    AIRLOCK_VAULT_PATH=:memory: \
    AIRLOCK_AUDIT_DB=:memory: \
    AIRLOCK_PROTECTION_LEVEL=balanced
WORKDIR /home/airlock
EXPOSE 8801
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8801/readyz', timeout=4).status == 200 else 1)"]

# ---------------------------------------------------------------- sidecar: + llama.cpp and Nano 4B
FROM ${LLAMA_IMAGE} AS llama

FROM demo-base AS sidecar
USER root
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /models && chown airlock:airlock /models
COPY --from=llama /app/ /opt/llama/
COPY --chmod=0755 deploy/sidecar-entrypoint.sh /usr/local/bin/airlock-sidecar
ENV LD_LIBRARY_PATH=/opt/llama \
    AIRLOCK_DETECTOR_BACKEND=local \
    AIRLOCK_LOCAL_BASE_URL=http://127.0.0.1:8091/v1 \
    AIRLOCK_LOCAL_MODEL=nemotron-3-nano-4b \
    AIRLOCK_LOCAL_TIMEOUT_S=90 \
    LLAMA_MODEL_PATH=/models/NVIDIA-Nemotron3-Nano-4B-Q4_K_M.gguf \
    LLAMA_MODEL_URL=https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF/resolve/main/NVIDIA-Nemotron3-Nano-4B-Q4_K_M.gguf
USER 10001:10001
CMD ["airlock-sidecar"]

FROM demo-base AS demo
ENV AIRLOCK_DETECTOR_BACKEND=cloud
USER 10001:10001
CMD ["airlock", "serve"]
