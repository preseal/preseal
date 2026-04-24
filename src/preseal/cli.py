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
    trials: int = typer.Option(10, help="Number of Pass³ trials per attack (min 3, default 10)"),
    save_baseline: bool = typer.Option(False, "--save-baseline", help="Save result as baseline for future diff"),
) -> None:
    """Scan an AI agent for security vulnerabilities using Pass³ methodology."""

    if not demo and not target:
        console.print("[red]Error: provide --target or use --demo[/red]")
        raise typer.Exit(1)

    if demo:
        report = _run_demo_scan(output, trials)
    else:
        report = _run_target_scan(target, output, trials)

    if save_baseline and report:
        from .baseline import save_baseline as _save
        path = _save(report)
        console.print(f"[dim]Baseline saved to: {path}[/dim]")


@app.command()
def diff(
    target: str = typer.Option(..., help="Agent target as module:object"),
    baseline_path: str = typer.Option(".preseal/baseline.json", help="Path to baseline file"),
    output: str = typer.Option("./preseal-report.json", help="Output report path"),
    trials: int = typer.Option(10, help="Trials per attack"),
) -> None:
    """Compare agent security against a saved baseline. Reports regressions."""
    from pathlib import Path as P
    from .baseline import load_baseline, compute_diff

    baseline = load_baseline(P(baseline_path))
    if baseline is None:
        console.print(f"[red]No baseline found at {baseline_path}[/red]")
        console.print("[dim]Run `preseal scan --target ... --save-baseline` first.[/dim]")
        raise typer.Exit(1)

    console.print(f"[dim]Baseline: {baseline.target} ({baseline.timestamp})[/dim]")

    report = _run_target_scan(target, output, trials)
    if report is None:
        raise typer.Exit(1)

    diff_report = compute_diff(baseline, report)

    if diff_report.regressions:
        console.print(f"\n[bold red]REGRESSIONS: {len(diff_report.regressions)} attack(s) got worse[/bold red]")
        for reg in diff_report.regressions:
            console.print(f"  [red]▼[/red] {reg.attack_name}: {reg.detail}")
    if diff_report.improvements:
        console.print(f"\n[green]Improvements: {len(diff_report.improvements)}[/green]")
        for imp in diff_report.improvements:
            console.print(f"  [green]▲[/green] {imp}")
    if diff_report.new_attacks:
        console.print(f"\n[yellow]New failing attacks: {len(diff_report.new_attacks)}[/yellow]")
        for na in diff_report.new_attacks:
            console.print(f"  [yellow]●[/yellow] {na}")
    if not diff_report.regressions and not diff_report.new_attacks:
        console.print("\n[bold green]No regressions detected.[/bold green]")

    console.print(f"\n[dim]{len(diff_report.unchanged)} attacks unchanged.[/dim]")

    if diff_report.has_regressions:
        raise typer.Exit(1)


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
def compare(
    baseline: str = typer.Option("", help="Baseline agent as module:object"),
    current: str = typer.Option("", help="Current agent as module:object"),
    demo: bool = typer.Option(False, help="Run demo: vulnerable vs secure agent"),
    trials: int = typer.Option(5, help="Trials per attack (5 is fast, 10 for confidence)"),
) -> None:
    """Compare two agent configs — find what changed between model swaps, prompt edits, or tool changes."""

    if demo:
        _run_demo_compare(trials)
        return

    if not baseline or not current:
        console.print("[red]Error: provide --baseline and --current, or use --demo[/red]")
        raise typer.Exit(1)

    import importlib
    from uuid import uuid4
    from .compare import compare_configs
    from .environment import RealEnvironmentManager
    from .demo import _get_demo_attacks

    def _load_agent(target_str):
        module_path, obj_name = target_str.rsplit(":", 1)
        mod = importlib.import_module(module_path)
        obj = getattr(mod, obj_name)
        if callable(obj) and not hasattr(obj, "invoke"):
            return obj()
        return obj

    try:
        agent_a = _load_agent(baseline)
        agent_b = _load_agent(current)
    except Exception as e:
        console.print(f"[red]Error loading agents: {e}[/red]")
        raise typer.Exit(1)

    canaries = [f"CANARY_PRESEAL_{uuid4().hex[:12]}" for _ in range(2)]
    attacks = _get_demo_attacks()

    env_a = RealEnvironmentManager(canary_tokens=canaries)
    env_b = RealEnvironmentManager(canary_tokens=canaries)

    console.print(f"[bold]preseal compare[/bold]")
    console.print(f"  Baseline: {baseline}")
    console.print(f"  Current:  {current}")
    console.print(f"  Trials:   {trials} per attack\n")

    try:
        report = compare_configs(
            agent_baseline=agent_a, agent_current=agent_b,
            attacks=attacks, baseline_label=baseline, current_label=current,
            trials=trials, canary_tokens=canaries,
            env_manager_baseline=env_a, env_manager_current=env_b,
        )
    finally:
        env_a.cleanup()
        env_b.cleanup()

    _output_compare(report)

    if report.has_regressions:
        raise typer.Exit(1)


def _run_demo_compare(trials: int) -> None:
    from .demo import run_demo_compare

    console.print(f"[bold]preseal compare --demo[/bold]")
    console.print("[dim]Comparing: vulnerable agent vs secure (hardened) agent[/dim]")
    console.print(f"[dim]Trials: {trials} per attack[/dim]\n")

    _r_vuln, _r_safe, delta = run_demo_compare(trials=trials)
    _output_compare(delta)


def _output_compare(report) -> None:
    table = Table(title="Configuration Delta")
    table.add_column("Attack", style="bold")
    table.add_column(report.baseline_label, justify="center")
    table.add_column(report.current_label, justify="center")
    table.add_column("Change", justify="center")

    for d in report.deltas:
        change_style = {
            "NEW_VULN": "[bold red]NEW VULN[/bold red]",
            "FIXED": "[bold green]FIXED[/bold green]",
            "DEGRADED": "[red]DEGRADED[/red]",
            "IMPROVED": "[green]IMPROVED[/green]",
            "UNCHANGED": "[dim]unchanged[/dim]",
        }
        table.add_row(
            d.attack_name,
            f"{d.baseline_verdict} ({d.baseline_fail_rate})",
            f"{d.current_verdict} ({d.current_fail_rate})",
            change_style.get(d.change, d.change),
        )

    console.print(table)
    console.print()

    if report.new_vulnerabilities:
        console.print(f"[bold red]{len(report.new_vulnerabilities)} NEW VULNERABILITIES introduced[/bold red]")
        for d in report.new_vulnerabilities:
            console.print(f"  [red]▼[/red] {d.attack_name}: {d.baseline_verdict} → {d.current_verdict}")
    if report.fixed:
        console.print(f"[bold green]{len(report.fixed)} vulnerabilities FIXED[/bold green]")
        for d in report.fixed:
            console.print(f"  [green]▲[/green] {d.attack_name}: {d.baseline_verdict} → {d.current_verdict}")
    if report.improved:
        console.print(f"[green]{len(report.improved)} improved[/green]")
    if not report.has_regressions and not report.new_vulnerabilities:
        console.print("[bold green]No regressions. Secure configuration is working.[/bold green]")


@app.command()
def version() -> None:
    """Show version."""
    console.print(f"preseal v{__version__}")


def _run_demo_scan(output: str, trials: int) -> "ScanReport":
    """Run scan against built-in vulnerable demo agent."""
    from .demo import run_demo_scan

    console.print(f"[bold]preseal v{__version__}[/bold]")
    console.print("[dim]Running demo scan (no API keys needed)...[/dim]\n")

    report = run_demo_scan(trials=trials)
    _output_report(report, output)
    return report


def _run_target_scan(target: str, output: str, trials: int) -> None:
    """Run scan against user-specified agent."""
    import importlib
    from uuid import uuid4

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
    from .environment import RealEnvironmentManager
    from .scanner import run_scan

    canary_tokens = [f"CANARY_PRESEAL_{uuid4().hex[:12]}" for _ in range(2)]
    env_mgr = RealEnvironmentManager(canary_tokens=canary_tokens)

    attacks = load_default_attacks()
    for attack in attacks:
        if not attack.setup_env:
            attack.setup_env = {}
        if attack.category.value == "exfiltration":
            attack.setup_env.setdefault("DB_PASSWORD", canary_tokens[0])
            attack.setup_env.setdefault("AWS_SECRET_ACCESS_KEY", canary_tokens[1])

    try:
        report = run_scan(
            agent=agent, attacks=attacks, target_name=target, trials=trials,
            canary_tokens=canary_tokens, env_manager=env_mgr,
        )
    finally:
        env_mgr.cleanup()

    _output_report(report, output)
    return report


def _output_report(report: ScanReport, output_path: str) -> None:
    """Display report in terminal and write JSON."""

    n_trials = max((len(r.trials) for r in report.results), default=0)

    table = Table(title=f"Preseal Scan — {report.target} ({n_trials} trials)")
    table.add_column("Attack", style="bold")
    table.add_column("Fail", justify="center")
    table.add_column("Verdict", justify="center")
    table.add_column("Fail Rate 95% CI", justify="center")
    table.add_column("Security", justify="right")
    table.add_column("Utility", justify="right")

    for result in report.results:
        failures = result.failure_count
        total = len(result.trials)
        fail_str = f"{failures}/{total}"
        if failures == total:
            fail_str = f"[red]{fail_str}[/red]"
        elif failures > 0:
            fail_str = f"[yellow]{fail_str}[/yellow]"
        else:
            fail_str = f"[green]{fail_str}[/green]"

        verdict_style = {
            Verdict.STRUCTURAL: "[bold red]STRUCTURAL[/bold red]",
            Verdict.STOCHASTIC: "[yellow]WARNING[/yellow]",
            Verdict.PASS: "[green]PASS[/green]",
        }

        lo, hi = result.failure_rate_ci
        ci_str = f"[{lo:.0%}, {hi:.0%}]"

        table.add_row(
            result.attack.name,
            fail_str,
            verdict_style[result.verdict],
            ci_str,
            f"{result.score.security_score:.2f}",
            f"{result.score.utility_score:.2f}",
        )

    console.print(table)
    console.print()

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

    console.print(f"Overall score: {report.overall_score:.3f}  (security × utility)")

    failed_results = [r for r in report.results if r.verdict != Verdict.PASS]
    if failed_results:
        console.print("\n[bold]Findings:[/bold]")
        for r in failed_results:
            console.print(f"\n  [bold red]{r.verdict.value.upper()}[/bold red]: {r.attack.name}  [dim]({r.owasp_id})[/dim]")
            if r.attack_reason:
                console.print(f"    Why: {r.attack_reason}")
            if r.fix_suggestion:
                console.print(f"    [dim]Fix: {r.fix_suggestion}[/dim]")

    console.print(f"\nReport written to: {output_path}")

    # JSON output
    Path(output_path).write_text(
        report.model_dump_json(indent=2, exclude={"results": {"__all__": {"trials": {"__all__": {"trajectory": True}}}}})
    )

    # Exit code
    if report.structural_count > 0:
        raise typer.Exit(1)
    elif report.stochastic_count > 0:
        raise typer.Exit(2)
