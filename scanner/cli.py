from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from scanner.engine import result_json, scan_paths
from scanner.models import Severity
from scanner.sarif import result_sarif
from scanner.scoring import summarize

app = typer.Typer(
    no_args_is_help=True,
    help="Local static security auditing for IaC and container configuration.",
)
console = Console()

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


@app.command()
def scan(
    paths: Annotated[list[Path], typer.Argument(exists=True, readable=True)],
    output_format: Annotated[str, typer.Option("--format", help="text, json, or sarif")] = "text",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    severity: Annotated[str, typer.Option("--severity")] = "info",
) -> None:
    """Scan files or directories.

    Exit status: 0 = no findings at or above --severity; 1 = qualifying findings;
    2 = at least one file could not be scanned (parse error, unreadable or oversized input)
    or the command was misused. 2 takes precedence over 1 so a CI gate cannot pass while
    part of the target went unscanned.
    """
    if output_format not in {"text", "json", "sarif"}:
        raise typer.BadParameter("format must be text, json, or sarif")
    try:
        threshold = list(Severity).index(Severity(severity.lower()))
    except ValueError as exc:
        raise typer.BadParameter("unknown severity") from exc

    result = scan_paths(paths)
    # Keep suppressed findings in machine-readable reports as an audit trail;
    # only active findings drive the text table, risk score, and exit status.
    reported = [
        finding
        for finding in result.findings
        if list(Severity).index(finding.severity) <= threshold
    ]
    visible = [finding for finding in reported if not finding.suppressed]
    suppressed_count = len(reported) - len(visible)
    result.findings = reported
    result.risk_score, result.severity_counts = summarize(reported)

    if output_format == "json":
        rendered = result_json(result)
    elif output_format == "sarif":
        rendered = result_sarif(result)
    else:
        table = Table(title=f"CloudSentry — {result.files_scanned} file(s) scanned")
        for column in ("Severity", "Rule", "Location", "Finding"):
            table.add_column(column)
        for finding in visible:
            table.add_row(
                finding.severity.value.upper(),
                finding.rule_id,
                f"{finding.file_path}:{finding.line_start or '?'}",
                finding.title,
            )
        with console.capture() as capture:
            console.print(table)
            console.print(f"Risk score: {result.risk_score}/100 (heuristic, not probability)")
            if suppressed_count:
                console.print(
                    f"{suppressed_count} suppressed finding(s) not shown; "
                    "--format json or --format sarif includes their reasons."
                )
            for warning in result.warnings:
                location = f"{warning.file_path}:{warning.line_start or '?'}"
                console.print(
                    f"[yellow]warning: {escape(location)}: {escape(warning.message)}[/yellow]"
                )
            for error in result.errors:
                text = f"{error.kind}: {error.file_path}: {error.message}"
                console.print(f"[red]{escape(text)}[/red]")
        rendered = capture.get()

    if output:
        output.write_text(rendered, encoding="utf-8")
    else:
        typer.echo(rendered, nl=False)

    if result.errors:
        typer.echo(
            f"cloudsentry: {len(result.errors)} file(s) could not be scanned; "
            "exiting with status 2.",
            err=True,
        )
        raise typer.Exit(code=EXIT_ERROR)
    raise typer.Exit(code=EXIT_FINDINGS if visible else EXIT_CLEAN)


@app.command()
def rules() -> None:
    for rule, description in [
        ("CS-DKR-001", "Dockerfile explicitly runs as root"),
        ("CS-DKR-002", "Mutable latest base image tag"),
        ("CS-DKR-003", "No USER instruction"),
        ("CS-CMP-001", "Privileged Compose service"),
        ("CS-CMP-002", "Host network mode"),
        ("CS-CMP-003", "Docker socket mount"),
        ("CS-CMP-004", "Wildcard host port binding"),
        ("CS-TF-001", "Public S3 ACL"),
        ("CS-TF-002", "World-open IPv4 CIDR"),
        ("CS-TF-003", "EBS encryption explicitly disabled"),
    ]:
        console.print(f"{rule:14} {description}")
