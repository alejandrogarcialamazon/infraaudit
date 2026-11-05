#!/usr/bin/env bash
# Solo lectura. No imprime tokens ni modifica la autenticación.
set -euo pipefail
expected_account="${1:-alejandrogarcialamazon}"
if ! command -v gh >/dev/null 2>&1; then
  echo 'GitHub CLI no está en PATH.' >&2
  exit 1
fi
if ! gh auth status --hostname github.com >/dev/null 2>&1; then
  echo 'No se pudo verificar GitHub. Revisar red y keyring antes de autenticar otra vez.' >&2
  exit 1
fi
actual_account="$(gh api user --jq .login)"
if [[ "$actual_account" != "$expected_account" ]]; then
  echo "Cuenta inesperada: $actual_account (esperada: $expected_account)" >&2
  exit 1
fi
printf 'GitHub disponible. Cuenta: %s\n' "$actual_account"
