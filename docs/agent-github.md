# GitHub desde Codex y OpenCode

La integración usa GitHub CLI (`gh`) y el gestor de credenciales de Git del usuario.
No requiere copiar tokens al proyecto ni configurar un MCP con secretos.

## Equipo de Alejandro

Verificado el 5 de noviembre de 2026:

- Cuenta activa: `alejandrogarcialamazon`.
- CLI: `/home/alejandro/.local/bin/gh`, accesible por PATH.
- Autenticación almacenada en el keyring del usuario.
- Git HTTPS ya usa `gh auth git-credential` como helper global.
- Codex: `~/.codex/AGENTS.md` contiene las reglas globales de GitHub.
- OpenCode: `~/.config/opencode/AGENTS.md` contiene las mismas reglas;
  `opencode.json` también referencia las instrucciones globales de Codex.
- El agente primario `github` de OpenCode está configurado con shell y edición
  sujetos a sus permisos. Iniciar con `opencode --agent github`.

Las sesiones locales que corren con el mismo usuario y acceden a ese keyring
comparten la autenticación. Las sesiones remotas, contenedores, otros usuarios y
conectores de la aplicación tienen accesos independientes. Cada sesión conserva
sus restricciones de red y permisos; un error dentro del sandbox no demuestra
que el token haya caducado. Verificar conectividad antes de volver a iniciar sesión.

## Comprobación

```bash
gh auth status
gh api user --jq .login
git remote -v
opencode --agent github
```

Nunca ejecutar `gh auth token`, leer archivos privados de credenciales ni pegar
secretos en prompts. El script `scripts/check_github.sh` comprueba acceso y cuenta
sin imprimir tokens y no modifica configuración.

## Instalación en otro equipo

Instalar Git y GitHub CLI, añadir `gh` al PATH y ejecutar:

```bash
gh auth login --hostname github.com --git-protocol https --web
gh auth setup-git --hostname github.com
```

El usuario completa el navegador. No se transporta el token del equipo original.
Conservar las reglas de acceso en los archivos globales de cada herramienta;
este repositorio aporta las reglas específicas mediante `AGENTS.md`.

Documentación oficial:

- [Codex: instrucciones AGENTS.md](https://developers.openai.com/codex/guides/agents-md/)
- [OpenCode: reglas globales y del proyecto](https://opencode.ai/docs/rules/)
- [OpenCode: agentes](https://opencode.ai/docs/agents/)
