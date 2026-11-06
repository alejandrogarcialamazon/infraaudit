# Mejora 04 — Validación estricta del inventario

Implementada el 06/11/2026. Publicación prevista: 17:10 Buenos Aires.

Los modelos de configuración rechazan campos desconocidos, cadenas obligatorias
vacías y números no finitos. Los IDs deben comenzar con letra o dígito y continuar
con letras, dígitos, guiones, puntos, dos puntos o guion bajo. Se verifican IDs
únicos por tipo de servicio y por host.

Se validan puertos SSH/TCP entre 1 y 65535, URLs HTTP/HTTPS con hostname y puerto
válidos, códigos HTTP esperados no vacíos entre 100 y599, y nombres de checks de
skip_checks contra el registro incluido. IPv6 entre corchetes está soportado.

Los umbrales de CPU, memoria, disco e inodos requieren 0 <= warn < crit <=100;
load y latencia requieren 0 <= warn < crit. Para días TLS se exige
0 <= crit_days < warn_days, dado que menor cantidad de días es peor.

La validación ocurre antes de iniciar SSH o consultas de red. Los errores indican
la ubicación del campo sin repetir valores ni credenciales. Un inventario que
antes ignoraba una opción mal escrita ahora falla explícitamente. La validación
comprueba estructura y coherencia, no disponibilidad, DNS ni permisos del destino.
Los skip_checks de plugins externos requieren integrar su registro antes de usarlos.

Pruebas: límites de puertos, URLs/esquemas/puertos incorrectos, campos desconocidos,
IDs repetidos, errores de skip_checks, umbrales invertidos, NaN, códigos HTTP e IPv6.
También se comprueba que un inventario inválido no abra SSH. Suite conjunta con
mejora03: 184 pruebas unitarias más cinco integraciones aprobadas; Ruff/Mypy y
construcción de wheel desde sdist correctos. Se valida la ejecución contra el host
Linux autorizado sin modificar sus cuentas ni servicios; resultados privados en out.
