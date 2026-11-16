# Mejora 14 — Reportes trazables y comparación

Implementada el 16/11/2026. Entrega 1.1.0 beta.

## Comportamiento

Esquema3.0 añade fingerprint del inventario redactado, workers, cancelled y finding_id derivado de check/target/kind/rule_id. Docker distingue cada regla y puertos distingue IPv4/IPv6, evitando identidades ambiguas. Los datos variables de medición no cambian la identidad.

Los archivos se escriben mediante temporal privado, flush/fsync y os.replace: un fallo no deja un reporte parcial ni destruye el anterior. diff clasifica new/persistent/resolved/not_comparable y cambios de severidad. Solo marca resuelto un hallazgo ausente cuyo check/target se completó en la nueva corrida.

## Uso

```bash
infraaudit diff previous.json current.json
```

## Validación

Pruebas de reemplazo atómico fallido, IDs estables con evidencia variable, severidad modificada y ausencia de falsos resueltos cuando faltan comprobaciones. Comparación del reporte remoto consigo mismo.

Los resultados y el estado de publicación de la entrega completa constan en
[VALIDACION-05-15.md](VALIDACION-05-15.md). Evidencia operativa privada en out,
excluida de Git.

## Límites

El fingerprint excluye/redacta secretos; no acredita credenciales idénticas. Reportes históricos con IDs ambiguos se rechazan para comparar; no se reescribe su evidencia. JSON anteriores siguen siendo legibles.
