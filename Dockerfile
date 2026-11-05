# Imagen de ejecución read-only para InfraAudit
FROM python:3.12-slim

LABEL org.opencontainers.image.title="InfraAudit" \
      org.opencontainers.image.description="CLI de auditorías técnicas Linux/Docker/Red" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples
COPY docs ./docs

RUN pip install --upgrade pip \
    && pip install .

RUN useradd --create-home --uid 10001 infraaudit \
    && mkdir -p /work \
    && chown -R infraaudit:infraaudit /work /app

USER infraaudit
WORKDIR /work

ENTRYPOINT ["infraaudit"]
CMD ["--help"]
