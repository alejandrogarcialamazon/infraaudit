# Mejora 08 — Resolución DNS tipada y acotada

Implementada el 16/11/2026. Entrega 1.1.0 beta.

## Comportamiento

Se elimina la dependencia de dig: dnspython 2.8.0 resuelve A, AAAA, CNAME, MX y TXT. Cada registro admite timeout, nameserver y port. timeout/lifetime acotan la consulta; no se usa la búsqueda de sufijos del sistema.

NXDOMAIN y NoAnswer son respuestas negativas observadas (HIGH operativo). Timeout, servidores no disponibles u otro error del resolver son inconclusos. La evidencia contiene dns_status. CNAME/MX normalizan mayúsculas y punto final; TXT concatena los fragmentos de datos sin las comillas de representación DNS.

## Uso

```bash
infraaudit run inventory.yml --check network.dns
```

## Validación

Pruebas de nombres/puertos explícitos, categorías de excepción y TXT multipartes; servidor UDP efímero real para respuesta positiva, NXDOMAIN y NoAnswer.

Los resultados y el estado de publicación de la entrega completa constan en
[VALIDACION-05-15.md](VALIDACION-05-15.md). Evidencia operativa privada en out,
excluida de Git.

## Límites

No valida DNSSEC ni implementa un resolver recursivo. El servidor explícito debe ser una dirección admitida por dnspython. No consulta dominios de clientes durante las pruebas.
