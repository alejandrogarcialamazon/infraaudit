# Mejora 01 — Estados de ejecución y cobertura de auditoría

Fecha: 5 de noviembre de 2026. Estado: implementada y validada localmente.

## Problema

Una salida vacía, un comando inexistente o permisos insuficientes podían producir
un resultado aparentemente saludable. Tampoco se contabilizaban los checks
omitidos o bloqueados por una conexión SSH fallida.

## Comportamiento nuevo

Cada `CheckResult` contiene `status`, `reason` y `diagnostic_evidence`:

| Estado | Significado |
| --- | --- |
| `completed` | Se obtuvieron datos suficientes y se interpretaron |
| `not_evaluated` | No hay datos suficientes: herramienta ausente, permisos, timeout o salida insuficiente |
| `error` | Fallo inesperado de ejecución o interpretación |
| `skipped` | Omitido explícitamente mediante inventario |

`success` se conserva para compatibilidad y solo es verdadero para `completed`.
Un check completado puede contener hallazgos CRITICAL: ejecución completa no
significa ausencia de problemas. Se rechazan valores contradictorios de status y
success al cargar JSON.

Los checks incluidos usan `CheckContext.command`: valida código de salida,
timeout y presencia de datos. Las listas legítimamente vacías (por ejemplo,
systemd sin unidades fallidas) son válidas únicamente si el comando tuvo éxito.
Se validan contadores y estructuras mínimas antes de interpretar recursos.
NTP requiere una respuesta explícita sobre sincronización; un servicio activo
por sí solo no la acredita.

Se eliminó la dependencia de jq para listar contenedores: el pipeline podía
ocultar un fallo de Docker detrás de una lista vacía. Se interpreta cada fila JSON
y se rechazan respuestas incompletas. DNS sin respuesta y TLS sin evidencia
suficiente quedan no evaluables; los hallazgos HTTP previos se conservan si la
inspección TLS adicional falla.

## Cobertura y CLI

JSON, Markdown y HTML muestran checks previstos, seleccionados, completados,
estados, motivos y porcentaje de cobertura. La cobertura se calcula como
completados / (previstos - omitidos). No mide salud ni cobertura de controles que
el inventario nunca solicitó. Cero checks seleccionados da 0% y auditoría incompleta.

Ante fallo SSH se registra un resultado no evaluable por cada check seleccionado.
`skip_checks` y `docker: false` generan resultados omitidos sin abrir conexiones
cuando no queda trabajo seleccionado. Categorías excluidas mediante `--only`
quedan fuera del alcance y del denominador.

CLI guarda reportes y devuelve 1 si la auditoría quedó incompleta, 2 si fue completa
y contiene CRITICAL, y 0 si fue completa sin CRITICAL. Se mantiene el código 2 de
argumentos inválidos propio de la CLI. Los reportes usan esquema 2.0; la CLI sigue
leyendo JSON anteriores y marca su esquema como 1.0. Los estados antiguos se
infieren de `success` y `error`, sin revalidar evidencia histórica.

## Pruebas

- 141 pruebas aprobadas en Linux/Python 3.14.4, incluidas regresiones parametrizadas
  sobre los 21 checks SSH: comando ausente, permisos insuficientes y timeout.
- Casos de salida vacía válida, datos malformados, memoria inconsistente, omisiones,
  error SSH por host, migración JSON, cobertura y escape HTML.
- Ruff y Mypy; construcción del paquete y validación del wheel.
- Prueba real autorizada sobre un host Linux por SSH estricto, sin sudo: 15 checks
  Linux completados y 6 Docker no evaluables porque Docker no está instalado.
  Cobertura 71,43%, auditoría incompleta y CLI con código 1.
- Sondas inocuas de comando inexistente y rechazo simulado: no evaluables sin
  hallazgos de seguridad inventados. JSON, Markdown y HTML generados.
- Metadatos de los archivos de sistema observados iguales antes y después.

Los inventarios, direcciones y reportes reales se guardan fuera del contenido
publicable. La herramienta corre desde la estación del auditor; el host no
necesita Python 3.12 ni instalación de InfraAudit. Docker operativo se prueba con
dobles controlados, no con un daemon real en ese host.

## Extensiones y límites

Los plugins deben usar `ctx.command` o lanzar `CheckNotEvaluableError` cuando no
puedan evaluar. Si ya obtuvieron hallazgos válidos, pueden conservarlos mediante
el argumento `findings`. Un plugin que fabrique datos saludables no puede ser
verificado automáticamente por el motor. Se mantiene pendiente el endurecimiento
del transporte SSH para comandos con mucha salida y timeout total.
