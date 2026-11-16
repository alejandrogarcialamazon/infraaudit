# Build reproducible desde locks, sin herramientas de desarrollo en runtime.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS builder
ENV PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY requirements-dev.lock requirements-runtime.lock ./
RUN pip install --require-hashes -r requirements-dev.lock
COPY pyproject.toml README.md LICENSE CHANGELOG.md ./
COPY src ./src
COPY docs ./docs
COPY tests ./tests
COPY examples ./examples
RUN python -m build --wheel --no-isolation

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
LABEL org.opencontainers.image.title="InfraAudit" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements-runtime.lock ./
RUN pip install --require-hashes -r requirements-runtime.lock
COPY --from=builder /src/dist/*.whl /tmp/wheels/
RUN pip install --no-deps /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels \
    && useradd --create-home --uid 10001 infraaudit \
    && mkdir -p /work && chown infraaudit:infraaudit /work
USER infraaudit
WORKDIR /work
ENTRYPOINT ["infraaudit"]
CMD ["--help"]
