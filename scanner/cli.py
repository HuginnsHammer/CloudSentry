from pathlib import Path
from typing import Annotated
import typer
from rich.console import Console
from rich.table import Table
from scanner.engine import result_json, scan_paths
from scanner.models import Severity
app = typer.Typer(no_args_is_help=True, help="Local static security auditing for IaC and container configuration.")
console = Console()

@app.command()
def scan(paths: Annotated[list[Path], typer.Argument(exists=True, readable=True)], format: Annotated[str, typer.Option("--format", help="text or json")] = "text", output: Annotated[Path | None, typer.Option("--output", "-o")] = None, severity: Annotated[str, typer.Option("--severity")] = "info") -> None:
    if format not in {"text", "json"}: raise typer.BadParameter("format must be text or json")
    try: threshold = list(Severity).index(Severity(severity.lower()))
    except ValueError as exc: raise typer.BadParameter("unknown severity") from exc
    result = scan_paths(paths)
    visible = [f for f in result.findings if list(Severity).index(f.severity) <= threshold and not f.suppressed]
    result.findings = visible
    from scanner.scoring import summarize
    result.risk_score, result.severity_counts = summarize(visible)
    if format == "json": rendered = result_json(result)
    else:
        table = Table(title=f"CloudSentry — {result.files_scanned} file(s) scanned")
        for col in ("Severity", "Rule", "Location", "Finding"): table.add_column(col)
        for f in visible: table.add_row(f.severity.value.upper(), f.rule_id, f"{f.file_path}:{f.line_start or '?'}", f.title)
        with console.capture() as capture:
            console.print(table); console.print(f"Risk score: {result.risk_score}/100 (heuristic, not probability)")
            for error in result.errors: console.print(f"[red]{error.kind}: {error.file_path}: {error.message}[/red]")
        rendered = capture.get()
    if output: output.write_text(rendered, encoding="utf-8")
    else: typer.echo(rendered, nl=False)
    raise typer.Exit(code=2 if result.status == "error" else 1 if visible else 0)

@app.command()
def rules() -> None:
    for rule, description in [("CS-DKR-001", "Dockerfile explicitly runs as root"), ("CS-DKR-002", "Mutable latest base image tag"), ("CS-DKR-003", "No USER instruction"), ("CS-CMP-001", "Privileged Compose service"), ("CS-CMP-002", "Host network mode"), ("CS-CMP-003", "Docker socket mount"), ("CS-CMP-004", "Wildcard host port binding"), ("CS-TF-001", "Public S3 ACL"), ("CS-TF-002", "World-open IPv4 CIDR"), ("CS-TF-003", "EBS encryption explicitly disabled")]: console.print(f"{rule:14} {description}")
