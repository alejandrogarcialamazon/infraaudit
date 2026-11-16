# Mejora 07 — HTTP y TLS coherentes

Implementada el 16/11/2026. Entrega 1.1.0 beta.

## Comportamiento

Cada servicio admite follow_redirects, inspect_tls, verify_tls y ca_bundle. La inspección usa el destino final tras redirecciones y la misma CA configurada. verify_tls=false emite advertencia y evita una segunda inspección contradictoria que exigiera certificados válidos. Una redirección HTTPS a HTTP se informa como fallo de seguridad.

min_days_to_expiry deja de ser ignorado: si se declara, sustituye el umbral global de advertencia. El umbral crítico global conserva prioridad. Deshabilitar inspect_tls se registra como omisión explícita de la inspección adicional; el handshake verificado sigue siendo independiente.

## Uso

```bash
infraaudit run inventory.yml --check network.http
```

## Validación

Pruebas de HTTP500, CA/expiración, certificado no confiable, destino final, umbral60d y verificación deshabilitada. Integraciones HTTP/TLS reales en loopback.

Los resultados y el estado de publicación de la entrega completa constan en
[VALIDACION-05-15.md](VALIDACION-05-15.md). Evidencia operativa privada en out,
excluida de Git.

## Límites

Los timeouts de HTTPX son por fase; la inspección TLS adicional tiene su propio timeout. Las CA privadas deben declararse explícitamente. No se envían métodos mutantes.
