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
from infraaudit.comparison import compare_reports
from infraaudit.config import InventoryError, validate_inventory_file
from infraaudit.diagnostics import doctor
from infraaudit.engine import AuditEngine
from infraaudit.logging_setup import setup_logging
from infraaudit.models import AuditReport, CheckCategory
from infraaudit.policy import exit_code
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
    host: Annotated[list[str] | None, typer.Option("--host", help="Host ID (repetible)")] = None,
    tag: Annotated[list[str] | None, typer.Option("--tag", help="Etiqueta de host (OR)")] = None,
    check: Annotated[list[str] | None, typer.Option("--check", help="Check ID (repetible)")] = None,
    workers: Annotated[int, typer.Option("--workers", min=1, max=32)] = 1,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Mostrar plan sin conectar")] = False,
    fail_on: Annotated[
        str, typer.Option("--fail-on", help="info|low|medium|high|critical|none")
    ] = "critical",
    incomplete: Annotated[str, typer.Option("--incomplete", help="fail|allow")] = "fail",
    summary_json: Annotated[bool, typer.Option("--summary-json")] = False,
    progress: Annotated[bool, typer.Option("--progress/--no-progress")] = True,
) -> None:
    """Ejecuta la auditoría (solo lectura) y genera resultados."""
    categories = _parse_only(only)
    if fail_on.lower() not in {"info", "low", "medium", "high", "critical", "none"}:
        raise typer.BadParameter("Severidad inválida", param_hint="--fail-on")
    if incomplete not in {"fail", "allow"}:
        raise typer.BadParameter("Use fail o allow", param_hint="--incomplete")
    try:
        get_reporter(format)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--format") from exc
    try:

        def on_progress(done: int, total: int) -> None:
            if progress:
                console.print(f"Progreso: {done}/{total}")

        engine = AuditEngine.from_path(
            inventory,
            only=categories,
            host_ids=host,
            tags=tag,
            check_ids=check,
            workers=workers,
            progress=on_progress,
        )
    except InventoryError as exc:
        console.print(f"[red]Inventario inválido:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if dry_run:
        typer.echo(json.dumps(engine.plan(), ensure_ascii=False))
        return
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
        f"coverage={summary['coverage_percent']}% complete={summary['complete']} "
        f"security_failed={summary['security_failed_checks']} "
        f"inconclusive={summary['inconclusive_checks']}"
    )
    if summary_json:
        typer.echo(json.dumps(summary, ensure_ascii=False))
    code = exit_code(report, fail_on.lower(), incomplete)
    if code:
        raise typer.Exit(code=code)


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
        console.print("[red]No se pudo leer results: JSON o esquema inválido[/red]")
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
            reporter.write(report, default)
            console.print(f"Escrito: [green]{default}[/green]")
        else:
            sys.stdout.write(rendered)
    else:
        reporter.write(report, output)
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


@app.command("doctor")
def doctor_cmd(
    inventory: Annotated[Path | None, typer.Argument()] = None,
    probe: Annotated[bool, typer.Option("--probe", help="Probar SSH explícitamente")] = False,
) -> None:
    try:
        data = validate_inventory_file(inventory) if inventory else None
        result = doctor(data, probe=probe)
    except (InventoryError, OSError) as exc:
        console.print(f"[red]Preflight inválido: {exc}[/red]")
        raise typer.Exit(1) from exc
    typer.echo(json.dumps(result, ensure_ascii=False))
    if not result["ready"]:
        raise typer.Exit(1)


@app.command("diff")
def diff_cmd(before: Path, after: Path) -> None:
    try:
        reports = []
        for path in (before, after):
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload.setdefault("schema_version", "1.0")
            reports.append(AuditReport.model_validate(payload))
        result = compare_reports(reports[0], reports[1])
    except (OSError, ValueError):
        console.print("[red]Reportes inválidos o identidades ambiguas[/red]")
        raise typer.Exit(1) from None
    typer.echo(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    app()
