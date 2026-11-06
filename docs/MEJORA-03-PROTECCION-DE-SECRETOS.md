# Mejora 03 — Protección de secretos

Implementada el 06/11/2026. Publicación prevista: 17:10 Buenos Aires.

Contraseñas y passphrases SSH usan SecretStr, quedan fuera de repr y de la
serialización del inventario, y solo se extraen al autenticar con Paramiko.
Los errores de YAML e inventario ya no repiten líneas ni valores del archivo.

La redacción de evidencia es recursiva: campos sensibles, credenciales en URLs,
tokens en parámetros, autenticación Bearer/Basic y secretos declarados en el
inventario. Los secretos conocidos se limitan a la ejecución mediante ContextVar,
sin dejar una lista global permanente ni mezclar auditorías. Se aplica al resultado
del check, informe agregado, JSON, HTML, Markdown y al formateador de logs de
InfraAudit. Los errores de plugins no imprimen tracebacks con credenciales.

La redacción conserva los estados tipados del motor. Los reportes históricos
pueden depurarse por claves y patrones reconocidos; una cadena arbitraria que no
esté identificada como credencial ni declarada en el inventario no puede
reconocerse automáticamente. Esto no anonimiza nombres, direcciones ni toda la
evidencia operativa; los informes siguen siendo privados por defecto. Tampoco
controla handlers de logging externos configurados por una aplicación integradora.

Pruebas: credenciales sintéticas en repr, dump, excepciones de validación, fallos
de plugins, logs, URLs y evidencias anidadas, con los tres formatos de reporte.
Suite conjunta de mejoras 03/04: 184 pruebas unitarias y cinco integraciones
HTTP/TCP/TLS aprobadas; Ruff, Mypy y wheel/sdist correctos. Auditoría SSH autorizada
sin sudo para validar compatibilidad; evidencia real excluida de Git en out.

No se publican inventarios reales ni credenciales. El documento operativo de
GitHub eliminado remotamente permanece eliminado.
