# Instalación y ejecución

## Requisitos

- Python **3.12+**
- Acceso SSH a los hosts auditados (clave o password vía env)
- Opcional: Docker Engine en hosts con `docker: true`
- Opcional: `dig` en la estación del auditor para DNS no-A/AAAA

## Instalación local

```bash
git clone https://github.com/alejandrogarcialamazon/infraaudit.git
cd infraaudit
python3.12 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]"
```

Verificar:

```bash
infraaudit version
infraaudit list-checks
infraaudit validate examples/inventory.example.yml
```

## Variables de entorno

| Variable | Uso |
| --- | --- |
| `INFRAAUDIT_SSH_USER` | Usuario SSH |
| `INFRAAUDIT_SSH_KEY` | Ruta a clave privada |
| `INFRAAUDIT_SSH_PASSWORD` | Password (alternativa) |
| `INFRAAUDIT_HOST_WEB` | Host de ejemplo web |
| `INFRAAUDIT_HOST_DB` | Host de ejemplo DB |
| `INFRAAUDIT_HTTP_URL` | URL HTTP de ejemplo |

Soporta interpolación `${VAR}` y `${VAR:-default}` en el YAML. Una variable requerida
sin definir impide ejecutar el inventario. El archivo `.env` no se carga automáticamente;
exportar las variables antes de ejecutar.

SSH requiere la clave del servidor en `~/.ssh/known_hosts`. Verificar el fingerprint
por un canal confiable antes de registrar el host. Las claves desconocidas o cambiadas
se rechazan. En Docker, montar también el archivo `known_hosts` junto con las claves.

## Ejecución

```bash
# Validar inventario
infraaudit validate examples/inventory.example.yml

# Auditoría completa
infraaudit run examples/inventory.example.yml -o results.json

# Solo Docker
infraaudit run examples/inventory.example.yml --only docker

# Solo red (desde la estación local)
infraaudit run examples/inventory.example.yml --only network

# Reportes
infraaudit report results.json --format markdown -o report.md
infraaudit report results.json --format html -o report.html
```

Códigos de salida:

| Code | Significado |
| --- | --- |
| 0 | Auditoría completa sin CRITICAL; puede contener HIGH/MEDIUM/LOW |
| 1 | Inventario inválido, conexión SSH fallida o check con error |
| 2 | Hallazgos CRITICAL o argumentos CLI inválidos (consultar stderr) |

## Docker

```bash
docker compose build
docker compose run --rm infraaudit validate /work/examples/inventory.example.yml

# Auditoría (montar SSH keys y usar network_mode: host si hace falta)
docker compose run --rm \
  -v "$HOME/.ssh:/home/infraaudit/.ssh:ro" \
  infraaudit run /work/examples/inventory.example.yml -o /work/out/results.json
```

## Desarrollo

```bash
pytest
ruff check src tests
mypy src
```

## Seguridad

- No almacenar passwords en el YAML en claro sin env vars.
- Preferir claves SSH con passphrase y `ssh-agent`.
- Ejecutar siempre desde una estación de confianza (la red se chequea localmente).
- Revisar `skip_checks` y `--only` antes de entregas a clientes.
