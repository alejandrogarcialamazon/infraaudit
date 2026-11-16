# Mejora 10 — Políticas de salida para automatización

Implementada el 16/11/2026. Entrega 1.1.0 beta.

## Comportamiento

run incorpora --fail-on info|low|medium|high|critical|none, --incomplete fail|allow y --summary-json. Los argumentos se validan antes de conectar. Los reportes siempre se guardan antes de devolver el estado.

Contrato:0 significa que no se incumplió la política;1 corresponde a auditoría incompleta con política fail;2 indica severidad igual o superior al umbral. La cancelación devuelve130 incluso si incomplete=allow. El valor predeterminado sigue siendo critical y fail. La CLI también usa2 para argumentos inválidos: consultar stderr para distinguirlo.

## Uso

```bash
infraaudit run inventory.yml --fail-on high --summary-json --no-progress
```

## Validación

Pruebas de umbrales info/high/critical/none, autorización explícita de incompletos, cancelación y JSON de resultados.

Los resultados y el estado de publicación de la entrega completa constan en
[VALIDACION-05-15.md](VALIDACION-05-15.md). Evidencia operativa privada en out,
excluida de Git.

## Límites

Con --incomplete allow se acepta expresamente cobertura parcial; no implica que el host esté saludable. El resumen JSON sale por stdout, progreso y mensajes humanos por stderr.
