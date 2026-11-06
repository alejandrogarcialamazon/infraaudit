# Mejora 02 del informe original — Transporte SSH con plazo total

Implementada el 06/11/2026. Push solicitado: 06/11/2026 18:15 Buenos Aires.
Esta entrega corresponde al endurecimiento SSH confirmado por el usuario. La
separación entre seguridad e inconclusos se documenta en su archivo independiente
MEJORA-02-SEGURIDAD-E-INCONCLUSOS.md y ya está publicada.

## Problema y corrección

Esperar recv_exit_status antes de consumir stdout ystderr podía bloquear un
comando cuya salida llenara la ventana SSH. Ahora se drenan ambos canales de
forma alternada, en bloques de32KiB, y se espera el estado final cuando los
buffers están vacíos y se recibió EOF o cierre del canal.

Se utiliza un plazo monotónico único por comando: apertura/ACK de exec y lectura
comparten el mismo presupuesto. No se renueva el plazo cuando llegan datos. Un
hilo daemon acota la espera del ACK de Paramiko; si no responde a tiempo, se cierra
la conexión. Si vence durante la lectura, se cierra el canal y se conserva la
sesión SSH para otros comandos cuando el transporte sigue disponible.

No se cambia la política estricta de known_hosts ni se amplía la deny-list como
supuesto aislamiento de plugins. El timeout no garantiza finalizar el proceso
remoto: limita la espera local y cierra su canal. Las conexiones y autenticación
conservan sus propios timeouts; el plazo nuevo se aplica a SSHClient.run.

## Evidencia acotada

HostConfig añade max_output_bytes: por defecto4194304 (4MiB), mínimo1024 y máximo
67108864 (64MiB). El límite es compartido por stdout ystderr. Al alcanzarlo se
sigue drenando y descartando la salida excedente para no bloquear la ventana.
CommandResult.truncated identifica la captura parcial y hace que ok sea falso,
aunque el comando finalice con código0. CheckContext.command la convierte en
resultado no evaluable, incluyendo la marca truncated en la evidencia técnica.

Ejemplo de inventario, sin credenciales reales:

```yaml
hosts:
  - id: servidor
    address: ${AUDIT_HOST}
    timeout: 15
    max_output_bytes: 8388608
    ssh:
      username: ${AUDIT_USER}
```

Los fallos de transporte producen comprobaciones inconclusas sin inventar
hallazgos de seguridad. Los cierres sin estado de salida se rechazan; los códigos
de salida no cero se conservan. Una captura truncada puede terminar con un
carácter de sustitución UTF-8 si el límite corta una secuencia multibyte; sigue
siendo evidencia parcial y no se interpreta como un check exitoso.

## Pruebas

- Suite local:203 pruebas unitarias más cinco integraciones HTTP/TCP/TLS.
- Casos nuevos: buffers grandes simultáneos, drenaje antes de exit status,
  alternancia de streams, salida continua, timeout total, ACK bloqueado, conexión
  interrumpida, cierre sin estado, salida126, límite combinado, UTF-8 dividido y
  validación del límite de evidencia.
- Ruff/Mypy y construcción de wheel ysdist; pruebas de CLI y reportes conservadas.
- Host Linux autorizado por SSH estricto sin sudo: lectura de3MiB stdout más3MiB
  stderr en0,213s; sin bloqueo ni truncamiento con límite8MiB.
- Segunda sonda: límite1KiB detectado y salida adicional drenada sin guardarla.
- Tercera sonda: proceso efímero de espera, timeout detectado en1,000s y posterior
  hostname exitoso reutilizando la sesión. Sin instalación de paquetes remotos.
- Auditoría completa:15 checks Linux completados, seis Docker no evaluables por
  herramienta ausente; sin errores del motor. Metadatos observados de archivos
  de sistema iguales antes/después. Evidencia privada en out/verification.

## Límites operativos

El cliente se usa secuencialmente: no compartir una instancia entre comandos
concurrentes. El límite acota los bytes retenidos de salida, no toda la memoria de
Paramiko ni la duración completa de una auditoría. El equipo que ejecuta la
publicación programada debe estar encendido, con red, keyring y NFS disponibles.
