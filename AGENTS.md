# InfraAudit — instrucciones para Codex y OpenCode

- Trabajar en español. CLI Python 3.12+, layout `src`, Typer, Pydantic y Paramiko.
- Leer README.md y docs/review.md antes de cambiar comportamiento o promesas del producto.
- Los checks deben consultar estado sin remediar ni modificar infraestructura.
- No ejecutar inventarios reales sin autorización sobre esos destinos. Usar mocks o loopback.
- No publicar inventarios privados, reportes de auditoría, `.env`, claves ni credenciales.
- Crear un venv en el sistema actual; los entornos virtuales no son portables entre sistemas.
- Validación: `python -m pytest`, `ruff check src tests`, `mypy src`, `python -m build`.
- Checks nuevos heredan BaseCheck y se registran en la categoría correspondiente.
- GitHub: usar `gh` con autenticación del usuario, verificar `gh auth status` y
  `gh api user --jq .login` antes de operar. Nunca leer ni mostrar tokens.
- Revisar `git diff --cached` y archivos antes de publicar. La autorización para
  esta publicación inicial no autoriza futuras publicaciones o cambios de visibilidad.
- En el equipo del propietario, OpenCode dispone de `opencode --agent github`.
  Consultar docs/agent-github.md para acceso compartido y diagnóstico.
