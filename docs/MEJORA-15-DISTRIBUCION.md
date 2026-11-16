# Mejora 15 — Versiones y distribución reproducible

Implementada el 16/11/2026. Entrega 1.1.0 beta.

## Comportamiento

Versión1.1.0 beta con una única fuente en __init__.py y metadata dinámica de Hatch. requirements-runtime.lock y requirements-dev.lock fijan versiones y hashes oficiales de PyPI para Linux CPython 3.12-3.14. Se instalan con --require-hashes. La construcción usa herramientas fijadas del lock y --no-isolation.

CI prueba el wheel instalado en un entorno limpio y una imagen multietapa no root, con base Python fijada por digest. scripts/release_artifacts.py genera sdist/wheel y SHA256SUMS, sin publicar en PyPI ni crear tags. CHANGELOG.md registra compatibilidad y cambios.

## Uso

```bash
pip install --require-hashes -r requirements-dev.lock
pip install --no-deps --no-build-isolation -e .
python scripts/release_artifacts.py
```

## Validación

Instalación limpia local validada con los hashes de los 49 paquetes del lock dev; wheel1.1.0 instalado y doctor/version correctos. Build de sdist y wheel. La imagen se valida en CI por no existir Docker local.

Los resultados y el estado de publicación de la entrega completa constan en
[VALIDACION-05-15.md](VALIDACION-05-15.md). Evidencia operativa privada en out,
excluida de Git.

## Límites

Locks orientados a Linux3.12-3.14; no certifican otros sistemas. No equivalen a bit reproducibility de cualquier artefacto externo. Actualizar dependencias requiere regenerar locks, revisar cambios y repetir la matriz de pruebas.
