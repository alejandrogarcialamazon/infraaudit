# Mejora 12 — Filtros y vista previa

Implementada el 16/11/2026. Entrega 1.1.0 beta.

## Comportamiento

run acepta --host, --tag y --check repetibles, además de --only. IDs desconocidos y filtros sin hosts coincidentes se rechazan. Etiquetas se combinan con OR; host y etiqueta se intersectan.

--dry-run imprime JSON con target/check/skip sin abrir SSH ni sockets de red. Los filtros de host/etiqueta limitan la auditoría a hosts SSH y excluyen los servicios de red independientes del inventario. --check puede seleccionar comprobaciones network sobre todos sus servicios declarados si no hay filtro de host.

## Uso

```bash
infraaudit run inventory.yml --tag web --check linux.cpu --dry-run
```

## Validación

Pruebas de plan exacto, rechazo de IDs desconocidos y ausencia de conexiones durante dry-run.

Los resultados y el estado de publicación de la entrega completa constan en
[VALIDACION-05-15.md](VALIDACION-05-15.md). Evidencia operativa privada en out,
excluida de Git.

## Límites

El plan describe trabajo declarado; no demuestra conectividad o permisos. Las omisiones de inventario se conservan como skipped y no se convierten en éxito.
