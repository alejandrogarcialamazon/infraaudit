# Mejora 09 — Ampliación de pruebas de integración

Implementada el 16/11/2026. Entrega 1.1.0 beta.

## Comportamiento

La suite añade servidores temporales DNS UDP y SSH Paramiko a las integraciones HTTP/TCP/TLS existentes. Usa sockets loopback, claves/certificados sintéticos y directorios de pytest. Las pruebas no dependen de infraestructura externa.

El servidor SSH verifica autenticación y known_hosts reales, transporta respuestas Docker controladas y comprueba que inspect no solicite campos sensibles. Los fixtures conservan canales hasta terminar y cierran sockets/transportes/hilos al finalizar.

## Uso

```bash
pytest --run-integration -m integration
```

## Validación

Siete escenarios de integración, además de las pruebas unitarias. CI ejecuta las integraciones en Python 3.12,3.13 y3.14.

Los resultados y el estado de publicación de la entrega completa constan en
[VALIDACION-05-15.md](VALIDACION-05-15.md). Evidencia operativa privada en out,
excluida de Git.

## Límites

No hay daemon Docker instalado en la estación ni en el host autorizado. La construcción y ejecución de la imagen se comprueban en un job Docker separado de GitHub Actions; no confundir ese job con el servidor Docker simulado.
