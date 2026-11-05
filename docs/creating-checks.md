# Guía: crear un nuevo check

## Contrato

Todo check hereda de `BaseCheck` e implementa `execute`:

```python
from infraaudit.checks.base import BaseCheck, CheckContext
from infraaudit.models import CheckCategory, Finding, Severity

class SwapCheck(BaseCheck):
    check_id = "linux.swap"
    category = CheckCategory.LINUX
    description = "Evalúa uso de swap"
    requires_ssh = True
    requires_docker = False

    def execute(self, ctx: CheckContext) -> list[Finding]:
        assert ctx.ssh is not None and ctx.host is not None
        result = ctx.ssh.run("cat /proc/swaps")
        lines = [ln for ln in result.stdout.splitlines()[1:] if ln.strip()]
        if not lines:
            return [
                self.finding(
                    severity=Severity.LOW,
                    target=ctx.host.id,
                    message="Sin swap configurado",
                    recommendation="Evaluar si el workload requiere swap",
                    evidence={"raw": result.stdout},
                )
            ]
        return [
            self.finding(
                severity=Severity.INFO,
                target=ctx.host.id,
                message=f"Swap entries: {len(lines)}",
                evidence={"raw": result.stdout.strip()},
            )
        ]
```

## Registro

Añadir la instancia a la lista correspondiente:

```python
# src/infraaudit/checks/linux/__init__.py
ALL_LINUX_CHECKS = [
    ...,
    SwapCheck(),
]
```

O registrar en runtime:

```python
from infraaudit.checks import build_default_registry
registry = build_default_registry()
registry.register(SwapCheck())
```

## Buenas prácticas

1. **Solo lectura**: nunca modificar estado remoto.
2. **Evidencia útil**: incluir salida parseada y cruda cuando aporte.
3. **Recomendación accionable**: qué hacer, no solo qué está mal.
4. **Severidad coherente** con umbrales de `ctx.thresholds` cuando aplique.
5. **Timeouts**: confiar en `ctx.ssh.run` / timeouts del inventario.
6. **Tests**: mockear `SSHClient.run` con `CommandResult`.
7. **IDs estables**: `categoria.nombre` (ej. `linux.swap`, `docker.security`).

## Checks de red (sin SSH)

```python
class MyNetCheck(BaseCheck):
    check_id = "network.custom"
    category = CheckCategory.NETWORK
    requires_ssh = False

    def execute(self, ctx: CheckContext) -> list[Finding]:
        service = ctx.extras["my_service"]
        ...
```

El engine debe pasar el objeto en `extras` (ver `AuditEngine._run_network_checks`).

## Categorías y filtros CLI

```bash
infraaudit run inventory.yml --only linux
infraaudit run inventory.yml --only docker,network
infraaudit list-checks
```

Por host se puede omitir checks:

```yaml
hosts:
  - id: web-01
    skip_checks: ["linux.mounts", "docker.volumes"]
```

## Evidencia insuficiente

Usar `ctx.command(comando)` para verificar código de salida y datos. Solo usar
`allow_empty=True` cuando una salida vacía exitosa tenga significado válido.
Lanzar `CheckNotEvaluableError(motivo, evidence=datos)` ante falta de herramientas,
permisos o evidencia; nunca sustituir datos desconocidos por cero o estado saludable.
Un resultado vacío del plugin se considera no evaluable. Ver la
[mejora 01](MEJORA-01-ESTADOS-Y-COBERTURA.md).
