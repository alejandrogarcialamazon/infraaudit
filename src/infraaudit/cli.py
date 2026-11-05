"""CLI de InfraAudit basada en Typer."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from infraaudit import __version__
from infraaudit.config import InventoryError, validate_inventory_file
from infraaudit.engine import AuditEngine
from infraaudit.logging_setup import setup_logging
from infraaudit.models import AuditReport, CheckCategory
from infraaudit.reporting import get_reporter, write_report

app = typer.Typer(
    name="infraaudit",
    help="Auditorías técnicas y health checks de infraestructura (read-only).",
    add_completion=False,
    no_args_is_help=True,
)
console = Console(stderr=True)


def _parse_only(values: list[str] | None) -> list[str] | None:
    if not values:
        return None
    normalized: list[str] = []
    for value in values:
        for part in value.split(","):
            part = part.strip().lower()
            if not part:
                continue
            try:
                CheckCategory(part)
            except ValueError as exc:
                raise typer.BadParameter(
                    f"Categoría inválida '{part}'. Use: linux, docker, network"
                ) from exc
            normalized.append(part)
    return normalized


@app.callback()
def main(
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Logging DEBUG"),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Solo warnings/errors"),
    ] = False,
) -> None:
    """InfraAudit CLI."""
    setup_logging(verbose=verbose, quiet=quiet)


@app.command("version")
def version_cmd() -> None:
    """Muestra la versión."""
    typer.echo(__version__)


@app.command("validate")
def validate_cmd(
    inventory: Annotated[Path, typer.Argument(help="Ruta al inventario YAML")],
) -> None:
    """Valida la sintaxis y el esquema del inventario."""
    try:
        data = validate_inventory_file(inventory)
    except InventoryError as exc:
        console.print(f"[red]Inventario inválido:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title="Inventario válido")
    table.add_column("Campo")
    table.add_column("Valor")
    table.add_row("name", data.name)
    table.add_row("hosts", str(len(data.hosts)))
    table.add_row("http_services", str(len(data.http_services)))
    table.add_row("tcp_services", str(len(data.tcp_services)))
    table.add_row("dns_records", str(len(data.dns_records)))
    console.print(table)
    console.print("[green]OK[/green]")


@app.command("run")
def run_cmd(
    inventory: Annotated[Path, typer.Argument(help="Ruta al inventario YAML")],
    only: Annotated[
        list[str] | None,
        typer.Option(
            "--only",
            help="Limitar categorías: linux, docker, network (repetible o CSV)",
        ),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Archivo JSON de resultados"),
    ] = Path("results.json"),
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="También exportar md/html además del JSON"),
    ] = "json",
) -> None:
    """Ejecuta la auditoría (solo lectura) y genera resultados."""
    categories = _parse_only(only)
    try:
        get_reporter(format)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--format") from exc
    try:
        engine = AuditEngine.from_path(inventory, only=categories)
    except InventoryError as exc:
        console.print(f"[red]Inventario inválido:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"Iniciando auditoría con inventario [cyan]{inventory}[/cyan] ...")
    report = engine.run(inventory_path=str(inventory))

    json_path = write_report(report, output, "json")
    console.print(f"Resultados JSON: [green]{json_path}[/green]")

    fmt = format.lower()
    if fmt not in {"json", ""}:
        ext = "md" if fmt in {"markdown", "md"} else fmt
        side = output.with_suffix(f".{ext}")
        write_report(report, side, fmt)
        console.print(f"Reporte adicional: [green]{side}[/green]")

    summary = report.summary()
    console.print(
        f"Hosts={summary['hosts']} findings={summary['total_findings']} "
        f"errors={summary['connection_errors']} "
        f"coverage={summary['coverage_percent']}% complete={summary['complete']}"
    )
    # Un informe incompleto nunca debe pasar como auditoría saludable.
    if not summary["complete"]:
        raise typer.Exit(code=1)
    if summary["by_severity"].get("CRITICAL", 0) > 0:
        raise typer.Exit(code=2)


@app.command("report")
def report_cmd(
    results: Annotated[Path, typer.Argument(help="Archivo results.json")],
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="json | markdown | html"),
    ] = "markdown",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Ruta de salida (default: stdout o archivo)"),
    ] = None,
) -> None:
    """Genera un reporte a partir de un results.json previo."""
    if not results.is_file():
        console.print(f"[red]No existe:[/red] {results}")
        raise typer.Exit(code=1)

    try:
        payload = json.loads(results.read_text(encoding="utf-8"))
        payload.setdefault("schema_version", "1.0")
        report = AuditReport.model_validate(payload)
    except Exception as exc:
        console.print(f"[red]No se pudo leer results:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    try:
        reporter = get_reporter(format)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    rendered = reporter.render(report)
    if output is None:
        if format.lower() == "html":
            default = results.with_suffix(".html")
            default.write_text(rendered, encoding="utf-8")
            console.print(f"Escrito: [green]{default}[/green]")
        else:
            sys.stdout.write(rendered)
    else:
        output.write_text(rendered, encoding="utf-8")
        console.print(f"Escrito: [green]{output}[/green]")


@app.command("list-checks")
def list_checks_cmd() -> None:
    """Lista los checks registrados."""
    from infraaudit.checks import build_default_registry

    registry = build_default_registry()
    table = Table(title="Checks disponibles")
    table.add_column("ID")
    table.add_column("Category")
    table.add_column("Description")
    for check in registry.all():
        table.add_row(check.check_id, check.category.value, check.description)
    console.print(table)


if __name__ == "__main__":
    app()
