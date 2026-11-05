# InfraAudit

CLI profesional para **auditorías técnicas y health checks** de infraestructura Linux, Docker y servicios de red.

Diseñada para consultoría, DevOps y SRE. Los checks incluidos consultan estado sin ejecutar remediaciones. **Estado: beta**; revisar las [limitaciones y evaluación](docs/review.md) antes de usarla en producción.

[![CI](https://github.com/alejandrogarcialamazon/infraaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/alejandrogarcialamazon/infraaudit/actions/workflows/ci.yml)

## Características

- Inventario YAML con hosts SSH, HTTP/TCP y DNS esperados
- Sistema de **plugins/checks** extensible (`BaseCheck` + `Finding`)
- Checks Linux: hostname, distro, kernel, uptime, CPU, memoria, load, filesystems, inodos, mounts, gateway, DNS, NTP, listening ports, systemd failed
- Checks Docker: versión, containers, health, resources, restart policy, privileged, root, healthchecks, networks, volumes
- Checks de red: DNS, TCP, HTTP/HTTPS, latencia, expiración TLS, issuer, SAN
- Reportes **JSON**, **Markdown** y **HTML**
- Estados de ejecución y cobertura explícita: completado, no evaluable, error y omitido
- Separación entre hallazgos de seguridad, problemas operativos y diagnósticos inconclusos
- Timeouts, logging, validación Pydantic, variables de entorno
- Empaquetado con `pyproject.toml`, tests (`pytest`), lint (`ruff`), types (`mypy`)

## Instalación rápida

```bash
git clone https://github.com/alejandrogarcialamazon/infraaudit.git
cd infraaudit
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
infraaudit version
```

Tras `pip install -e .` el comando `infraaudit` queda disponible de inmediato.

## CLI

```bash
infraaudit validate inventory.yml
infraaudit run inventory.yml
infraaudit run inventory.yml --only docker
infraaudit run inventory.yml --only linux,network -o results.json -f html
infraaudit report results.json --format html
infraaudit list-checks
```

## Inventario (ejemplo)

```yaml
name: prod-audit
hosts:
  - id: web-01
    address: ${WEB_HOST}
    ssh:
      username: ${INFRAAUDIT_SSH_USER}
      private_key: ${INFRAAUDIT_SSH_KEY}
    docker: true

http_services:
  - id: api
    url: https://api.example.com/health
    expected_status: [200]

tcp_services:
  - id: pg
    host: db.example.com
    port: 5432

dns_records:
  - id: api-a
    name: api.example.com
    record_type: A
    expected: ["203.0.113.10"]
```

Ver `examples/inventory.example.yml` y `.env.example`. Las variables deben estar exportadas en el entorno; `.env` no se carga automáticamente. Para SSH, registrar previamente la clave del host en `~/.ssh/known_hosts` tras verificar su fingerprint.

## Modelo Finding

| Campo | Descripción |
| --- | --- |
| `severity` | `INFO` \| `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` |
| `check` | Identificador del check |
| `target` | Host / servicio / recurso |
| `message` | Descripción del hallazgo |
| `recommendation` | Acción sugerida |
| `evidence` | Datos crudos (dict) |

## Arquitectura (resumen)

```text
inventory.yml → AuditEngine → CheckRegistry → Findings → JSON/MD/HTML
                     │
                     ├─ SSH (Linux/Docker checks)
                     └─ Local (DNS/TCP/HTTP/TLS)
```

Documentación detallada:

- [Arquitectura](docs/architecture.md)
- [Crear nuevos checks](docs/creating-checks.md)
- [Instalación y ejecución](docs/installation.md)
- [Manual PDF](docs/InfraAudit.pdf)
- [Evaluación y límites de la beta](docs/review.md)
- [Mejora 01: estados y cobertura](docs/MEJORA-01-ESTADOS-Y-COBERTURA.md)
- [Mejora 02: seguridad e inconclusos](docs/MEJORA-02-SEGURIDAD-E-INCONCLUSOS.md)

## Docker

```bash
docker compose build
docker compose run --rm infraaudit validate /work/examples/inventory.example.yml
```

## Desarrollo

```bash
pytest
ruff check src tests
mypy src
```

## Principios

1. Checks de diagnóstico sin remediación; la deny-list SSH es una defensa parcial, no un sandbox
2. **Sin secretos en código** — solo env vars / archivos de clave
3. **Extensible** — un check = una clase
4. **Entregable a cliente** — HTML autocontenido y Markdown limpio

## Licencia

MIT — ver [LICENSE](LICENSE).
