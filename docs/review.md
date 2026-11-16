# Evaluación vigente de InfraAudit — 16/11/2026

Versión1.1.0 beta. La arquitectura separa configuración, transporte, checks,
motor y reportes. Las mejoras05 a15 del informe original están implementadas;
cada una dispone de su documento MEJORA-XX y de evidencia de validación en
[VALIDACION-05-15.md](VALIDACION-05-15.md).

Se incorporan mediciones CPU por intervalo, NTP conservador, consultas Docker
selectivas, DNS tipado, confianza y redirecciones HTTP/TLS, políticas de salida,
preflight, filtros/plan, concurrencia y cancelación, reportes atómicos comparables
y dependencias fijadas con hashes. Se conservan los estados independientes de
salud/ejecución y las medidas de confidencialidad previas.

## Límites pendientes

- La deny-list SSH es una defensa parcial, no un sandbox de plugins. Usar permisos
  mínimos y destinos autorizados; la herramienta no remedia infraestructura.
- El timeout SSH limita la espera local y puede dejar el proceso remoto en curso.
  La cancelación es cooperativa y espera operaciones activas con sus timeouts.
- Las pruebas Docker de protocolo son controladas; la imagen real se prueba en
  CI. No se certifica el comportamiento de todas las versiones del daemon.
- Reportes con identidades históricas ambiguas no pueden compararse de forma
  fiable y se rechazan; los archivos anteriores siguen siendo legibles.
- La redacción no anonimiza toda la evidencia. Datos arbitrarios que no estén
  identificados como secretos pueden requerir revisión antes de compartirlos.
- Los locks se orientan a Linux CPython3.12-3.14. Otros sistemas necesitan su
  validación. Los plugins deben respetar el contrato de datos y ser seguros para
  ejecución concurrente entre hosts.
- No se carga .env automáticamente ni se incluye un scanner de vulnerabilidades,
  remediación, validación DNSSEC o una política de publicación PyPI automática.

## Compatibilidad

El esquema JSON nuevo es3.0 e incluye fingerprint e identidad de hallazgos.
Las opciones anteriores y los reportes legacy se conservan. Cambian deliberadamente
los diagnósticos basados antes en datos acumulados o ambiguos; revisar las reglas
y cobertura al comparar contra auditorías previas. Ver CHANGELOG.md.
