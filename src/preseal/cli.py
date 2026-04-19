"""CLI for preseal — pre-deployment AI agent security testing."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .models import ScanReport, Verdict

app = typer.Typer(
    name="preseal",
    help="Pre-deployment security testing for AI agents.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    target: str = typer.Option(
        "", help="Agent target as module:object (e.g., my_agent:agent)"
    ),
    demo: bool = typer.Option(False, help="Run against built-in vulnerable demo agent"),
    output: str = typer.Option(
        "./preseal-report.json", help="Output report path"
    ),
    trials: int = typer.Option(3, help="Number of Pass³ trials per attack"),
) -> None:
    """Scan an AI agent for security vulnerabilities using Pass³ methodology."""

    if not demo and not target:
        console.print("[red]Error: provide --target or use --demo[/red]")
        raise typer.Exit(1)

    if demo:
        _run_demo_scan(output, trials)
    else:
        _run_target_scan(target, output, trials)


@app.command()
def audit(
    file: str = typer.Argument(help="Path to Python file containing agent definition"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Static security audit of an AI agent file. Zero API calls, instant results."""
    from .audit import audit_file

    result = audit_file(file)

    if json_output:
        import json as json_mod
        data = {
            "file": result.file_path,
            "model": result.model,
            "temperature": result.temperature,
            "tools": [{"name": t.name, "risk": t.risk_level, "description": t.description} for t in result.tools],
            "system_prompt_detected": result.system_prompt is not None,
            "prompt_score": result.prompt_score,
            "overall_score": result.overall_score,
            "findings": [{"severity": f.severity, "category": f.category, "message": f.message, "fix": f.fix} for f in result.findings],
        }
        console.print_json(json_mod.dumps(data, indent=2))
        if result.high_count > 0:
            raise typer.Exit(1)
        return

    # Rich terminal output
    console.print(f"\n[bold]PRESEAL AUDIT[/bold] — {result.file_path}\n")

    # Config summary
    config_table = Table(show_header=False, box=None, padding=(0, 2))
    config_table.add_column("Key", style="dim")
    config_table.add_column("Value")
    config_table.add_row("Model", result.model or "[dim]not detected[/dim]")
    config_table.add_row("Temperature", str(result.temperature) if result.temperature is not None else "[dim]not detected[/dim]")
    config_table.add_row("Tools", f"{len(result.tools)} detected")
    config_table.add_row("System Prompt", f"{len(result.system_prompt)} chars" if result.system_prompt else "[red]NOT FOUND[/red]")
    console.print(config_table)
    console.print()

    # Tools
    if result.tools:
        for tool in result.tools:
            icon = {"high": "[red]HIGH[/red]", "medium": "[yellow]MED[/yellow]", "low": "[green]LOW[/green]"}
            console.print(f"  {icon.get(tool.risk_level, 'LOW'):>15}  {tool.name}" + (f" — {tool.description[:60]}" if tool.description else ""))
        console.print()

    # Findings
    if result.findings:
        for f in result.findings:
            icon = {"high": "[bold red]⚠ HIGH[/bold red]", "medium": "[yellow]⚠ MED[/yellow]", "low": "[dim]● LOW[/dim]", "info": "[dim]ℹ INFO[/dim]"}
            console.print(f"  {icon.get(f.severity, '')}  {f.message}")
            if f.fix:
                console.print(f"         [dim]Fix: {f.fix}[/dim]")
        console.print()

    # Score
    score = result.overall_score
    color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
    console.print(f"  Security Score: [{color}][bold]{score}/100[/bold][/{color}]")
    console.print()

    if score < 40:
        console.print("  [red]CRITICAL: This agent has significant security gaps.[/red]")
    elif score < 70:
        console.print("  [yellow]WARNING: Some security improvements recommended.[/yellow]")
    else:
        console.print("  [green]GOOD: Basic security patterns detected.[/green]")

    console.print(f"\n  [dim]Run `preseal scan --target {file}:agent` for adversarial testing.[/dim]")

    if result.high_count > 0:
        raise typer.Exit(1)
    elif result.medium_count > 0:
        raise typer.Exit(2)


@app.command()
def version() -> None:
    """Show version."""
    console.print(f"preseal v{__version__}")


def _run_demo_scan(output: str, trials: int) -> None:
    """Run scan against built-in vulnerable demo agent."""
    from .demo import run_demo_scan

    console.print(f"[bold]preseal v{__version__}[/bold]")
    console.print("[dim]Running demo scan (no API keys needed)...[/dim]\n")

    report = run_demo_scan(trials=trials)
    _output_report(report, output)


def _run_target_scan(target: str, output: str, trials: int) -> None:
    """Run scan against user-specified agent."""
    import importlib

    if ":" not in target:
        console.print("[red]Error: target must be module:object format[/red]")
        raise typer.Exit(1)

    module_path, obj_name = target.rsplit(":", 1)

    try:
        mod = importlib.import_module(module_path)
        agent_or_factory = getattr(mod, obj_name)
    except (ImportError, AttributeError) as e:
        console.print(f"[red]Error loading {target}: {e}[/red]")
        raise typer.Exit(1)

    if callable(agent_or_factory) and not hasattr(agent_or_factory, "invoke"):
        agent = agent_or_factory()
    else:
        agent = agent_or_factory

    from .attacks.loader import load_default_attacks
    from .scanner import run_scan

    attacks = load_default_attacks()
    report = run_scan(agent=agent, attacks=attacks, target_name=target, trials=trials)
    _output_report(report, output)


def _output_report(report: ScanReport, output_path: str) -> None:
    """Display report in terminal and write JSON."""

    # Terminal output
    table = Table(title=f"Preseal Scan — {report.target}")
    table.add_column("Attack", style="bold")
    table.add_column("T1", justify="center")
    table.add_column("T2", justify="center")
    table.add_column("T3", justify="center")
    table.add_column("Verdict", justify="center")
    table.add_column("Score", justify="right")

    for result in report.results:
        trials_display = []
        for t in result.trials:
            if t.attack_succeeded:
                trials_display.append("[red]FAIL[/red]")
            else:
                trials_display.append("[green]PASS[/green]")

        while len(trials_display) < 3:
            trials_display.append("-")

        verdict_style = {
            Verdict.STRUCTURAL: "[bold red]STRUCTURAL[/bold red]",
            Verdict.STOCHASTIC: "[yellow]WARNING[/yellow]",
            Verdict.PASS: "[green]PASS[/green]",
        }

        table.add_row(
            result.attack.name,
            trials_display[0],
            trials_display[1],
            trials_display[2],
            verdict_style[result.verdict],
            f"{result.score.total:.2f}",
        )

    console.print(table)
    console.print()

    # Summary
    if report.structural_count > 0:
        console.print(
            f"[bold red]RESULT: {report.structural_count} STRUCTURAL "
            f"vulnerabilities found[/bold red]"
        )
    elif report.stochastic_count > 0:
        console.print(
            f"[yellow]RESULT: {report.stochastic_count} stochastic warnings[/yellow]"
        )
    else:
        console.print("[bold green]RESULT: All attacks passed[/bold green]")

    console.print(f"Overall score: {report.overall_score:.3f}/1.000")
    console.print(f"Report written to: {output_path}")

    # JSON output
    Path(output_path).write_text(
        report.model_dump_json(indent=2, exclude={"results": {"__all__": {"trials": {"__all__": {"trajectory": True}}}}})
    )

    # Exit code
    if report.structural_count > 0:
        raise typer.Exit(1)
    elif report.stochastic_count > 0:
        raise typer.Exit(2)
