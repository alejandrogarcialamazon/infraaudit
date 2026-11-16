# Mejora 05 — CPU y sincronización NTP

Implementada el 16/11/2026. Entrega 1.1.0 beta.

## Comportamiento

CPU ahora toma dos muestras de /proc/stat separadas por 0,2s. Usa los ocho contadores base, excluye guest/guest_nice para evitar doble conteo y considera idle+iowait como tiempo no ocupado. Un delta nulo, negativo o inconsistente es no evaluable. La evidencia incluye intervalo, delta y porcentaje.

NTP consulta NTPSynchronized en formato máquina y valida Stratum de chrony entre 1 y 15. NTP interpreta respuestas explícitas de timedatectl y chronyc. Un servicio activo no acredita sincronización; fuentes contradictorias producen HIGH, nunca INFO. Sin respuesta interpretable queda inconcluso.

## Uso

```bash
infraaudit run inventory.yml --check linux.cpu --check linux.ntp
```

## Validación

Pruebas: delta50%, contadores reiniciados/sin delta, fuentes NTP normales, negativas y contradictorias. Comprobación adicional sobre host Linux autorizado sin sudo.

Los resultados y el estado de publicación de la entrega completa constan en
[VALIDACION-05-15.md](VALIDACION-05-15.md). Evidencia operativa privada en out,
excluida de Git.

## Límites

El porcentaje corresponde al intervalo observado, no a utilización instantánea permanente. No modifica configuración NTP ni carga CPU artificialmente.
