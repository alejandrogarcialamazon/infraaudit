# Mejora 13 — Concurrencia, progreso y cancelación

Implementada el 16/11/2026. Entrega 1.1.0 beta.

## Comportamiento

--workers admite1 a32 (predeterminado1). El executor limita tareas activas; cada tarea de host usa su propia sesión SSH y ejecuta sus checks secuencialmente. Servicios DNS/TCP/HTTP son tareas independientes. Los resultados se ordenan por inventario, no por el orden de finalización.

El progreso cuenta tareas de host/servicio. CTRL+C activa cancelación cooperativa: no se abren nuevas conexiones de tareas pendientes; las comprobaciones restantes se registran no evaluables y se preservan resultados ya obtenidos. El reporte lleva cancelled=true y la CLI devuelve130.

## Uso

```bash
infraaudit run inventory.yml --workers 4 --no-progress
```

## Validación

Pruebas de límite de tres tareas con ocho servicios, orden estable y cancelación simulada con resultados parciales.

Los resultados y el estado de publicación de la entrega completa constan en
[VALIDACION-05-15.md](VALIDACION-05-15.md). Evidencia operativa privada en out,
excluida de Git.

## Límites

La primera cancelación espera las operaciones activas hasta sus timeouts. No promete interrupción instantánea ni mata procesos remotos. Los plugins externos deben ser seguros para ejecución concurrente entre hosts.
