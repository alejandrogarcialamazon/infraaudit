# Mejora 02 — Fallos de seguridad y comprobaciones inconclusas

Fecha: 5 de noviembre de 2026. Prioridad alta. Depende de la mejora 01.

Esta entrega corresponde al alcance solicitado expresamente: distinguir fallos
de seguridad de comprobaciones inconclusas. El endurecimiento del transporte SSH
para grandes salidas y timeout total sigue como trabajo independiente.

## Problema corregido

El manejador genérico del plugin convertía cualquier excepción en un hallazgo
HIGH. Un problema del auditor podía confundirse con un problema de seguridad del
host. Los errores HTTP y TCP tampoco distinguían claramente falta de evidencia
de un incumplimiento observado.

## Tres dimensiones independientes

1. `status`: ejecución (`completed`, `not_evaluated`, `error`, `skipped`).
2. `assessment`: diagnóstico (`passed`, `failed`, `inconclusive`, `skipped`, `unknown`).
3. `Finding.kind`: naturaleza del hallazgo (`security`, `operational`, `unclassified`).

`security_failed` indica si existe evidencia explícita de un hallazgo de seguridad
con severidad superior a INFO. Los campos derivados se recalculan al cargar un
reporte: no se confía en un assessment o security_failed recibido en el JSON.
`success` conserva exclusivamente su significado de ejecución completa.

| Situación | Diagnóstico | Hallazgo de seguridad |
| --- | --- | --- |
| Docker no instalado o sin permisos | Inconcluso | No se inventa |
| Plugin falla por una excepción | Inconcluso; status error | No se inventa HIGH |
| Contenedor privileged confirmado | Fallo | Sí, CRITICAL |
| HTTP devuelve 500 | Fallo operativo | No |
| DNS, proxy o timeout impiden consultar HTTP/TCP | Inconcluso | No |
| Puerto TCP rechaza conexión | Fallo operativo desde el punto del auditor | No |
| Política de confianza TLS rechaza certificado | HTTP inconcluso | Sí, rechazo TLS confirmado |
| Certificado verificado próximo a expirar | Fallo | Sí, según umbral |

Los fallos de confianza TLS se reconocen por `SSLCertVerificationError` en la
cadena de excepciones; no se deducen buscando palabras en el mensaje. El rechazo
indica incumplimiento de la confianza configurada en el auditor, no prueba por sí
solo una vulnerabilidad explotable ni distingue una CA privada faltante.

Los checks de configuración de mounts, bindings de puertos y seguridad Docker
clasifican sus hallazgos como seguridad. Una advertencia de bind en todas las
interfaces no demuestra accesibilidad exterior: no se evalúa el firewall.

## Evidencia parcial y reportes

Una comprobación puede quedar inconclusa y conservar hallazgos confirmados. Por
ejemplo, HTTP puede completarse y luego fallar la inspección TLS adicional. Si ya
se confirmó un contenedor privileged antes de encontrar otro inspect incompleto,
el hallazgo se conserva y el check queda inconcluso.

JSON (esquema 2.1), Markdown, HTML y el resumen CLI muestran por separado los
checks inconclusos y los fallos de seguridad confirmados. Los informes históricos
sin clasificación conservan `unclassified`; los resultados antiguos sin estado
quedan marcados `legacy` y no se reinterpretan como diagnósticos certificados.

Los contadores de severidad globales incluyen todos los hallazgos, también los
operativos e históricos. Para seguridad usar `security_findings` y
`security_failed_checks`. `by_assessment` separa los resultados de diagnóstico.

Una auditoría incompleta devuelve 1 incluso si conserva un hallazgo grave; una
completa con CRITICAL devuelve 2. Las severidades inferiores por sí solas no
cambian el código de salida. No se añadió una política nueva `--fail-on`.

## Validación

- 162 pruebas unitarias y de regresión aprobadas en Python 3.14.4.
- Cinco pruebas de integración aprobadas con servidores HTTP/TCP/TLS temporales
  en loopback: salud, HTTP 500, certificado no confiable, certificado confiable
  próximo a expirar y CLI con conexión TCP rechazada.
- Las pruebas TLS generan certificados y claves efímeros, sin guardar secretos en
  Git. Las pruebas de integración se habilitan con `pytest --run-integration -m integration`.
- Nuevos casos de permisos, excepciones del plugin, DNS, proxy, timeout, evidencia
  parcial, clasificación histórica y recálculo de campos derivados.
- Ruff, Mypy, build y validación de wheel desde sdist.
- Auditoría real autorizada por SSH estricto a un host Linux sin sudo: 15 checks
  completados, seis Docker inconclusos porque Docker no está instalado. Un check
  de bindings produjo dos advertencias de seguridad MEDIUM; las seis consultas
  inconclusas no generaron hallazgos de seguridad. Código de salida 1.
- Sondas inocuas de herramienta ausente y permiso denegado simulado correctas;
  metadatos observados de archivos de sistema iguales antes y después.

La CI ejecutará también las integraciones en Python 3.12/3.13/3.14 después del push
programado. No se presupone su resultado futuro. No se ejecutaron remediaciones,
se instalaron paquetes remotos ni se probaron vulnerabilidades deliberadas en
infraestructura real. Docker operativo se verificó con dobles de prueba.

## Extender los checks

Los plugins de seguridad deben declarar `finding_kind = FindingKind.SECURITY` o
pasar `kind=FindingKind.SECURITY` a `self.finding` cuando exista evidencia del
control. El valor predeterminado de `self.finding` es operativo. Los Finding
construidos directamente sin kind quedan sin clasificar.

Usar `CheckNotEvaluableError(motivo, evidence=datos, findings=hallazgos_confirmados)`
para conservar evidencia parcial. Los errores técnicos van en reason/error y
`diagnostic_evidence`, sin fabricar hallazgos con severidad de seguridad.
