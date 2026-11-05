# InfraAudit — Manual técnico

**Versión 1.0.0** · Auditorías read-only de infraestructura Linux, Docker y red

---

## 1. Introducción

InfraAudit es una herramienta CLI reutilizable para realizar auditorías técnicas y
health checks de infraestructura. Está orientada a equipos de consultoría, DevOps y SRE
que necesitan evidencia reproducible, hallazgos priorizados por severidad y reportes
entregables al cliente.

La herramienta **no ejecuta acciones destructivas ni de remediación**. Su alcance es
exclusivamente de lectura y diagnóstico.

## 2. Objetivos

- Inventariar y evaluar hosts Linux de forma remota vía SSH
- Auditar runtime Docker (estado, seguridad, recursos)
- Validar servicios de red (DNS, TCP, HTTP/TLS) desde la estación del auditor
- Producir hallazgos estructurados (`Finding`) con evidencia y recomendaciones
- Exportar resultados a JSON, Markdown y HTML

## 3. Arquitectura

Componentes principales:

1. **CLI (Typer)** — `validate`, `run`, `report`, `list-checks`
2. **Config** — inventario YAML + expansión de variables de entorno + Pydantic
3. **Engine** — orquesta checks por categoría y host
4. **SSH Client** — Paramiko con timeouts y bloqueo de comandos peligrosos
5. **Check plugins** — subclases de `BaseCheck` registradas en `CheckRegistry`
6. **Reporting** — JSON / Markdown / HTML

Flujo:

```
Inventario YAML
    → Validación
    → Conexión SSH por host (linux/docker)
    → Checks de red locales
    → Agregación AuditReport
    → Exporters
```

## 4. Modelo de datos

### Severidades

| Severidad | Uso típico |
| --- | --- |
| INFO | Inventario / estado saludable |
| LOW | Mejora recomendada |
| MEDIUM | Riesgo moderado o degradación |
| HIGH | Problema importante a remediar pronto |
| CRITICAL | Riesgo inmediato o indisponibilidad |

### Finding

Cada check produce cero o más hallazgos con: `severity`, `check`, `target`,
`message`, `recommendation`, `evidence`.

## 5. Checks incluidos

### Linux

hostname, distribution, kernel, uptime, CPU, memory, load average, filesystems,
inode usage, mounts, gateway, DNS resolvers, NTP, listening ports, systemd failed units.

### Docker

version, containers (running/stopped/health), resource usage, restart policy,
privileged containers, containers as root, healthchecks, networks, volumes.

### Network

DNS records, TCP port connectivity, HTTP/HTTPS status + latency, TLS expiry,
issuer, SAN.

## 6. Inventario YAML

El inventario declara hosts, servicios HTTP/TCP, registros DNS y umbrales.
Las credenciales se inyectan con `${VAR}` o `${VAR:-default}`.

Nunca incluir passwords en claro en repositorios.

## 7. Uso de la CLI

```bash
pip install -e .
infraaudit validate examples/inventory.example.yml
infraaudit run examples/inventory.example.yml --only network -o results.json
infraaudit report results.json --format html -o report.html
```

Filtros:

- `--only linux|docker|network`
- `skip_checks` por host en el YAML

## 8. Extensión

1. Crear clase que herede `BaseCheck`
2. Implementar `execute(ctx) -> list[Finding]`
3. Registrar en `ALL_LINUX_CHECKS` / `ALL_DOCKER_CHECKS` / `ALL_NETWORK_CHECKS`
4. Añadir tests con SSH fake / monkeypatch

## 9. Seguridad operativa

- Preferir autenticación por clave + agent
- Verificar fingerprints y registrar hosts en `known_hosts`; SSH rechaza claves desconocidas
- Limitar el usuario SSH a permisos de lectura necesarios (`sudo` sin password solo si es imprescindible y acotado)
- Revisar deny-list de `ssh.py` antes de añadir comandos nuevos
- Conservar `results.json` como evidencia de auditoría

## 10. Empaquetado y calidad

- Python 3.12+
- `pytest` para unit tests
- `ruff` para lint
- `mypy` para tipos
- `Dockerfile` + `docker-compose.yml` para ejecución reproducible

## 11. Limitaciones conocidas

- Checks DNS CNAME/MX/TXT requieren `dig` en el PATH del auditor
- Uso de CPU vía `/proc/stat` es una aproximación de un snapshot
- No reemplaza un vulnerability scanner ni un CSPM cloud
- Ver [review.md](review.md) para la evaluación y límites de la beta

## 12. Licencia

MIT.

## 13. Estados de ejecución y cobertura

Los reportes distinguen `completed`, `not_evaluated`, `error` y `skipped`.
Una comprobación completada puede detectar hallazgos graves. El porcentaje de
cobertura mide checks completados sobre seleccionados, excluyendo omisiones
explícitas. Una auditoría sin trabajo o con checks no evaluables es incompleta
y la CLI devuelve 1 tras guardar evidencia. Ver
[mejora 01](MEJORA-01-ESTADOS-Y-COBERTURA.md) para compatibilidad y pruebas.
