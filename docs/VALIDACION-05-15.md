# Validación de mejoras 05 a 15 — 16/11/2026

Versión: 1.1.0 beta. Publicación solicitada antes de las17:59 Buenos Aires.

## Evidencia local

- 238 pruebas unitarias y siete integraciones HTTP/TCP/TLS/DNS/SSH aprobadas.
- Ruff sin errores y Mypy sin problemas en27 archivos fuente.
- Cobertura general de la suite completa aproximadamente84%; no se presenta como
  validación exhaustiva de cada plataforma o versión de Docker.
- Instalación en un venv limpio con --require-hashes:48 paquetes del lock dev,
  sin omitir la verificación de hashes. Wheel1.1.0 instalado sin depender del layout
  src; version y doctor ejecutados correctamente.
- Build de sdist y wheel desde el sdist; herramientas de construcción fijadas.
- Pruebas de escritura atómica fallida, políticas de salida, planificación sin red,
  concurrencia limitada, cancelación y comparación conservadora de hallazgos.

## Host autorizado

SSH estricto con clave existente y sin sudo. Preflight local y sonda SSH explícita
correctos. La auditoría completó15 checks Linux y uno TCP del puerto SSH conocido.
Seis checks Docker quedaron no evaluables porque la herramienta no está instalada.
No se instalaron paquetes ni se modificaron cuentas, servicios, red o claves.

CPU usa un intervalo real aproximado de0,2s; NTP consulta el estado de máquina.
La selección de CPU/NTP produjo una auditoría completa de dos checks. Se exportaron
JSON/HTML/Markdown y la comparación del reporte consigo mismo no informó hallazgos
nuevos ni resueltos. La auditoría completa devolvió1 por cobertura incompleta,
conservando las advertencias de bindings observadas sin inventar problemas Docker.

Inventarios, direcciones y evidencia real permanecen en out/verification, excluido
de Git. Los tests publicables utilizan localhost y valores sintéticos.

## Reproducibilidad y CI

Los hashes y versiones de los locks proceden de metadatos oficiales de PyPI.
La caché local permitió validar la instalación aunque files.pythonhosted.org
resolviera a una dirección local que rechazaba conexiones. No se modificó DNS ni
se deshabilitaron controles de integridad. dnspython2.8.0 se instaló desde su wheel
oficial previamente almacenado y validado contra el lock.

La estación y el host autorizado carecen de Docker: no se afirma una ejecución
local real de daemon ni construcción local de la imagen. El protocolo CLI Docker
se prueba mediante servidor SSH efímero con respuestas controladas. GitHub Actions
incluye un job separado que construye y ejecuta la imagen, más pruebas del wheel
instalado y una matriz Python3.12/3.13/3.14. Su resultado se consulta después del push.

La base de Docker se fija por digest, las herramientas del builder están en el
lock dev y el runtime instala solo el lock runtime y el wheel. No se publica en
PyPI ni se crean tags automáticamente; scripts/release_artifacts.py prepara los
artefactos y sus SHA256SUMS para revisión.

Fuentes técnicas: [dnspython Resolver](https://dnspython.readthedocs.io/en/stable/resolver-class.html).
