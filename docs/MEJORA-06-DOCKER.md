# Mejora 06 — Diagnósticos Docker confiables

Implementada el 16/11/2026. Entrega 1.1.0 beta.

## Comportamiento

Los comandos se cachean dentro de la auditoría de cada host, sin compartir snapshots entre hosts ni corridas. Se distingue herramienta ausente, permisos insuficientes, daemon inaccesible y otros resultados inconclusos mediante docker_status y el código/stderr de origen. Una lista vacía solo es válida tras comando exitoso.

inspect solicita exclusivamente nombre, usuario, modo de healthcheck, privileged, restart policy y estado del healthcheck. No extrae Env, labels, mounts ni logs de healthchecks. Los hallazgos llevan rule_id por control y se conserva evidencia parcial si otro objeto es inválido.

## Uso

```bash
infraaudit run inventory.yml --only docker
```

## Validación

Pruebas parametrizadas de fallos, cache y JSON/filas inválidas; integración con servidor SSH Paramiko real efímero y respuestas Docker controladas.

Los resultados y el estado de publicación de la entrega completa constan en
[VALIDACION-05-15.md](VALIDACION-05-15.md). Evidencia operativa privada en out,
excluida de Git.

## Límites

El host autorizado no tiene Docker. No se instaló allí ni se ejecutaron contenedores privilegiados reales. La integración simula el protocolo CLI, no certifica todas las versiones de daemon.
