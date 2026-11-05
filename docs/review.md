# Evaluación de publicación y funcionamiento

Revisión: 5 de noviembre de 2026.

## Conveniencia

Conviene publicar InfraAudit como beta: la separación entre inventario, checks,
motor y reportes permite reutilizarlo y ampliar los diagnósticos. La licencia MIT
ya incluida habilita reutilización y contribuciones. El proyecto aporta una base
para consultoría y health checks, pero necesita más validación en plataformas
reales antes de presentarlo como una herramienta de producción consolidada.

El número de versión existente es 1.0.0; el estado de madurez declarado es beta.
La publicación del repositorio no implica una publicación en PyPI ni una release
estable. Los ejemplos usan destinos ficticios o loopback y variables de entorno.

## Correcciones incluidas en la publicación inicial

- Error SSH o check fallido devuelve código 1 después de guardar evidencia.
- Un formato de salida inválido se rechaza antes de abrir conexiones.
- Variables requeridas sin definir impiden usar un inventario incompleto.
- Los hosts sin checks seleccionados no abren conexiones SSH.
- SSH carga `known_hosts` y rechaza claves desconocidas o cambiadas.
- DNS sin respuesta ya no se presenta como INFO saludable; un nameserver
  explícito también se respeta para A y AAAA.
- TCP usa `create_connection`, compatible con resolución IPv4/IPv6, y captura
  errores de conexión y de creación del socket.
- URLs del paquete, documentación e instrucciones de agentes apuntan al repositorio.
- CI con permisos de lectura y matriz Python 3.12, 3.13 y 3.14.

## Validación ejecutada

Sobre Linux con Python 3.14.4, usando un entorno virtual creado en este sistema:

- 31 pruebas de pytest aprobadas.
- Ruff sin errores y Mypy sin problemas en 23 archivos fuente.
- Construcción de sdist y wheel; wheel construido desde el sdist.
- CLI: `version`, `list-checks` y `validate` ejecutados correctamente.
- Auditoría real de un servidor HTTP/TCP temporal en loopback: dos checks
  exitosos, findings INFO y código 0.
- Exportación JSON, HTML y Markdown verificada.
- Repetición con el servidor apagado: hallazgos CRITICAL y código 2.
- Casos SSH y Docker verificados mediante mocks; no se auditó infraestructura
  real ni se ejecutó una imagen Docker durante esta revisión.

Las pruebas de CI en GitHub complementan esta revisión local con las versiones
Python declaradas. El estado actual se consulta en la pestaña Actions.

## Límites y trabajo siguiente

1. La deny-list SSH es una defensa parcial; no garantiza aislamiento frente a
   plugins arbitrarios. Usar cuentas y permisos mínimos en destinos autorizados.
2. La mejora 01 incorpora estados y cobertura para evitar resultados saludables
   ante fuentes fallidas o insuficientes. Ver MEJORA-01-ESTADOS-Y-COBERTURA.md.
   Los plugins externos deben adoptar el contrato de evidencia.
3. El transporte SSH espera el exit status antes de drenar stdout/stderr. Comandos
   con mucha salida pueden atascarse por la ventana del canal; hace falta validar
   streaming y timeout total antes de auditorías de gran tamaño.
4. La CPU se estima desde contadores acumulados y no mide utilización instantánea.
   NTP requiere revisar la interpretación de sincronización y sus fuentes.
5. DNS CNAME/MX/TXT y cualquier consulta a nameserver explícito requieren `dig`.
   Los errores de resolución se informan como ausencia de respuesta; aún no se
   distinguen NXDOMAIN, timeout y falta de la utilidad.
6. Un reporte puede contener nombres, direcciones y evidencia sensible. Guardarlo
   fuera de Git y revisar su contenido antes de compartirlo.
7. No se carga `.env` automáticamente. Las variables deben exportarse en el shell.
8. Los códigos de salida informan auditoría incompleta o CRITICAL; HIGH/MEDIUM/LOW
   por sí solos no causan fallo. El código 2 también corresponde a argumentos CLI
   inválidos; consultar stderr para distinguirlos.
9. Faltan validación Docker end-to-end, pruebas SSH con servidores reales
   autorizados y una política de versiones/dependencias reproducibles.

Prioridad siguiente: evitar falsos saludables por falta de datos, robustecer el
transporte SSH y ampliar cobertura de Docker/HTTP/TLS. Ver la CI antes de adoptar
un commit para uso operativo.
