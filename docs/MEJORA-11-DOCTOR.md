# Mejora 11 — Diagnóstico previo

Implementada el 16/11/2026. Entrega 1.1.0 beta.

## Comportamiento

doctor verifica Python, biblioteca DNS y, si se proporciona inventario, existencia del archivo de clave y presencia del destino en known_hosts. Los identificadores se muestran sin leer ni imprimir claves privadas ni valores de credenciales.

Por defecto no abre conexiones. --probe autoriza explícitamente una conexión SSH y el comando inocuo true. SSHAuth admite known_hosts para un archivo específico, útil en entornos aislados; nunca deshabilita la verificación de claves.

## Uso

```bash
infraaudit doctor inventory.yml
infraaudit doctor inventory.yml --probe
```

## Validación

Pruebas de ausencia de conexiones por defecto y selección del archivo de claves conocidas. Preflight y sonda SSH del host autorizado.

Los resultados y el estado de publicación de la entrega completa constan en
[VALIDACION-05-15.md](VALIDACION-05-15.md). Evidencia operativa privada en out,
excluida de Git.

## Límites

La presencia de una clave no garantiza permisos suficientes para todos los checks. doctor no instala dependencias, agrega claves de hosts ni cambia la configuración.
