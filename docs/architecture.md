# Arquitectura de InfraAudit

## Visión

InfraAudit es una CLI de auditoría **read-only** orientada a consultoría, DevOps y SRE.
Consume un inventario YAML, ejecuta checks no destructivos (SSH + red local) y produce
hallazgos (`Finding`) exportables a JSON, Markdown y HTML.

## Diagrama lógico

```text
┌─────────────┐     ┌──────────────┐     ┌────────────────────┐
│ inventory.yml│────▶│ AuditEngine  │────▶│ reporters (json/md │
└─────────────┘     │              │     │ html)              │
                    │  CheckRegistry│     └────────────────────┘
                    └──────┬───────┘
           ┌───────────────┼────────────────┐
           ▼               ▼                ▼
     Linux checks    Docker checks    Network checks
     (via SSH)       (via SSH)        (local auditor)
```

## Componentes

| Módulo | Responsabilidad |
| --- | --- |
| `cli.py` | Interfaz Typer (`validate`, `run`, `report`, `list-checks`) |
| `config.py` | Carga YAML, expansión `${ENV}`, validación Pydantic |
| `models.py` | `Finding`, `CheckResult`, `HostResult`, `AuditReport`, severidades |
| `ssh.py` | Cliente Paramiko con timeouts y **deny-list** de comandos destructivos |
| `engine.py` | Orquestación por host/categoría |
| `checks/` | Plugins de checks (`BaseCheck` + registry) |
| `reporting/` | Serialización a JSON/Markdown/HTML |

## Modelo de Finding

```python
Finding(
  severity,      # INFO | LOW | MEDIUM | HIGH | CRITICAL
  check,         # id del check, p.ej. linux.memory
  target,        # host, servicio o recurso
  message,       # descripción humana
  recommendation,# acción sugerida
  evidence,      # dict con datos crudos
)
```

## Extensibilidad

1. Crear una subclase de `BaseCheck`.
2. Implementar `execute(ctx) -> list[Finding]`.
3. Registrar la instancia en `ALL_*_CHECKS` o en un registry custom.
4. El engine la descubrirá automáticamente vía `build_default_registry()`.

Ver [creating-checks.md](creating-checks.md).

## Garantías read-only

- No hay comandos de remediación, restart, delete ni write.
- `SSHClient` bloquea patrones peligrosos (`rm`, `docker rm`, `systemctl restart`, etc.).
- Los checks Docker usan `ps`, `inspect`, `stats`, `network ls`, `volume ls`.
- Las credenciales se inyectan por variables de entorno / claves; nunca se hardcodean.

## Flujo de ejecución

1. `validate` — valida esquema sin conectar.
2. `run` — conecta SSH por host, ejecuta checks filtrados (`--only`), corre checks de red.
3. Persiste `results.json`.
4. `report` — regenera Markdown/HTML desde el JSON.

## Timeouts y errores

- Timeout SSH configurable por host (`timeout`) y global (`default_timeout`).
- HTTP/TCP con timeouts propios.
- Fallos de check se convierten en `Finding` HIGH con evidencia del error; no abortan toda la corrida.
- Fallo de conexión SSH se registra en `HostResult.connection_error`.

## Decisiones de diseño

1. **Pydantic v2** para contratos claros y mensajes de validación útiles en consultoría.
2. **Plugins por herencia** (`BaseCheck`) en lugar de entry-points complejos: simple de auditar y enseñar.
3. **Paramiko síncrono** para portabilidad y control fino de timeouts (asyncssh queda como evolución).
4. **Severidades fijas** alineadas a prácticas de riesgo (INFO→CRITICAL) para priorizar remediación.
5. **Reportes autocontenidos** (HTML sin CDN) para entregar al cliente offline.
6. **Separación network vs host**: checks de red salen desde la estación del auditor; Linux/Docker vía SSH.
