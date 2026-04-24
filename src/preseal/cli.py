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
    quick: bool = typer.Option(False, help="Fast scan: 10 key attacks × 3 trials (~60s with LLM)"),
    output: str = typer.Option(
        "./preseal-report.json", help="Output report path"
    ),
    trials: int = typer.Option(0, help="Trials per attack (0 = auto: 3 for quick, 10 for full)"),
    concurrency: int = typer.Option(5, help="Parallel trials per attack (default 5)"),
    save_baseline: bool = typer.Option(False, "--save-baseline", help="Save result as baseline for future diff"),
) -> None:
    """Scan an AI agent for security vulnerabilities using Pass³ methodology."""

    if not demo and not target:
        console.print("[red]Error: provide --target or use --demo[/red]")
        raise typer.Exit(1)

    if trials == 0:
        trials = 3 if (quick or demo) else 10

    if demo:
        report = _run_demo_scan(output, trials)
    else:
        report = _run_target_scan(target, output, trials, concurrency, quick)

    if save_baseline and report:
        from .baseline import save_baseline as _save
        path = _save(report)
        console.print(f"[dim]Baseline saved to: {path}[/dim]")

    if report:
        if quick and report.structural_count > 0:
            console.print(f"\n[dim]Quick scan found issues. Run full scan for complete coverage:[/dim]")
            console.print(f"[dim]  preseal scan --target {target}[/dim]")
        if report.structural_count > 0:
            raise typer.Exit(1)
        elif report.stochastic_count > 0:
            raise typer.Exit(2)


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
def init(
    path: str = typer.Argument(".", help="Project root directory"),
) -> None:
    """Set up preseal in your project. Detects agents, providers, and generates config."""
    from pathlib import Path as P
    from .detect import detect_project

    root = P(path).resolve()
    console.print(f"\n[bold]preseal init[/bold] — {root}\n")

    info = detect_project(root)

    # Sort agents: prefer objects named "agent"/"app", then by confidence, then shorter path
    if info.agents:
        active_providers = {p.name for p in info.providers if p.is_set}

        def _agent_sort_key(a):
            name_priority = 0 if a.object_name in ("agent", "app", "bot") else 1
            conf_priority = 0 if a.confidence == "high" else 1
            path_len = len(a.module_path)
            return (name_priority, conf_priority, path_len, a.module_path)
        info.agents.sort(key=_agent_sort_key)

    # 1. Show what we found
    console.print("[bold]Detected:[/bold]")

    if info.agents:
        for agent in info.agents[:3]:
            icon = "[green]✓[/green]" if agent.confidence == "high" else "[yellow]~[/yellow]"
            console.print(f"  {icon} Agent: [bold]{agent.target}[/bold] ({agent.framework})")
        if len(info.agents) > 3:
            console.print(f"  [dim]  ...and {len(info.agents) - 3} more[/dim]")
    else:
        console.print("  [yellow]No agents found.[/yellow] preseal needs a Python object with .invoke() or a callable.")
        console.print("  [dim]Point preseal at your agent: preseal scan --target my_module:my_agent[/dim]")

    if info.providers:
        for prov in info.providers:
            icon = "[green]✓[/green]" if prov.is_set else "[yellow]○[/yellow]"
            status = "set" if prov.is_set else f"found in {prov.source} but not exported"
            console.print(f"  {icon} Provider: {prov.name} ({prov.env_var} {status})")
    else:
        console.print("  [dim]No LLM provider detected. preseal audit works without one.[/dim]")
        console.print("  [dim]For preseal scan, set your agent's API key (e.g. OPENAI_API_KEY, ANTHROPIC_API_KEY)[/dim]")

    console.print()

    # 2. Create .preseal/ directory
    preseal_dir = root / ".preseal"
    preseal_dir.mkdir(exist_ok=True)

    # 3. Generate config
    config_path = preseal_dir / "config.yaml"
    if not config_path.exists():
        target = info.agents[0].target if info.agents else "my_module:my_agent"
        config_content = f"""# preseal project configuration
# Generated by `preseal init`

# Your agent target (module:object format)
target: "{target}"

# Number of trials per attack (higher = more confident, slower)
trials: 10

# Attack sources: "builtin" uses preseal's 57 built-in attacks, "custom" adds your own
attacks:
  - builtin
  # - ./attacks/  # uncomment to add custom YAML attacks

# CI behavior
ci:
  fail_on: structural  # "structural" = hard block, "stochastic" = also fail on warnings
  audit_threshold: 40   # minimum audit score to pass
"""
        config_path.write_text(config_content)
        console.print(f"[green]Created[/green] {config_path.relative_to(root)}")
    else:
        console.print(f"[dim]Config already exists: {config_path.relative_to(root)}[/dim]")

    # 4. Run initial audit if we found an agent
    if info.agents:
        agent = info.agents[0]
        agent_file = root / agent.file_path
        if agent_file.exists():
            console.print(f"\n[bold]Running initial audit on {agent.file_path}...[/bold]\n")
            from .audit import audit_file
            result = audit_file(str(agent_file))
            color = "green" if result.overall_score >= 70 else "yellow" if result.overall_score >= 40 else "red"
            console.print(f"  Security Score: [{color}][bold]{result.overall_score}/100[/bold][/{color}]")
            if result.findings:
                high = sum(1 for f in result.findings if f.severity == "high")
                med = sum(1 for f in result.findings if f.severity == "medium")
                if high:
                    console.print(f"  [red]{high} HIGH findings[/red]")
                if med:
                    console.print(f"  [yellow]{med} MEDIUM findings[/yellow]")
            console.print(f"  [dim]Run `preseal audit {agent.file_path}` for details.[/dim]")

    # 5. Verify agent if we have one and a provider key
    agent_verified = False
    if info.agents and any(p.is_set for p in info.providers):
        agent = info.agents[0]
        console.print(f"\n[bold]Verifying agent...[/bold]")
        try:
            import importlib
            for _p in [str(root), str(root / "src")]:
                if _p not in sys.path:
                    sys.path.insert(0, _p)
            mod = importlib.import_module(agent.module_path)
            agent_obj = getattr(mod, agent.object_name)
            if callable(agent_obj) and not hasattr(agent_obj, "invoke"):
                agent_obj = agent_obj()
            from .scanner import verify_agent
            ok, err = verify_agent(agent_obj)
            if ok:
                console.print(f"  [green]✓[/green] Agent responds — ready for scanning")
                agent_verified = True
            else:
                console.print(f"  [yellow]○[/yellow] Agent verification failed: {err[:100]}")
        except Exception as e:
            console.print(f"  [yellow]○[/yellow] Could not verify agent: {str(e)[:100]}")

    # 6. Show next steps
    console.print("\n[bold]Next steps:[/bold]")
    target_hint = info.agents[0].target if info.agents else "my_module:my_agent"

    step = 1
    if not info.providers or not any(p.is_set for p in info.providers):
        console.print(f"  {step}. Export your API key:  [bold]export OPENAI_API_KEY=sk-...[/bold]  (or ANTHROPIC_API_KEY, etc.)")
        step += 1

    if agent_verified:
        console.print(f"  {step}. Quick scan (~60s): [bold]preseal scan --target {target_hint} --quick[/bold]")
    else:
        console.print(f"  {step}. Quick scan (~60s): [bold]preseal scan --target {target_hint} --quick[/bold]")
    step += 1
    console.print(f"  {step}. Full scan + save:  [bold]preseal scan --target {target_hint} --save-baseline[/bold]")
    step += 1

    if not info.has_ci_workflow:
        console.print(f"  {step}. Add to CI:         [bold]preseal show-workflow > .github/workflows/agent-security.yml[/bold]")

    console.print()


@app.command()
def doctor() -> None:
    """Diagnose preseal setup — checks Python, providers, agents, attacks, CI."""
    from .detect import detect_project

    console.print(f"\n[bold]preseal doctor[/bold]\n")

    info = detect_project()
    issues = 0
    warnings = 0

    # Python version
    major, minor = info.python_version.split(".")[:2]
    if int(minor) >= 9:
        console.print(f"  [green]✓[/green] Python {info.python_version}")
    else:
        console.print(f"  [red]✗[/red] Python {info.python_version} — preseal requires 3.9+")
        issues += 1

    # Preseal version
    console.print(f"  [green]✓[/green] preseal {info.preseal_version}")

    # langchain-core
    try:
        import langchain_core
        console.print(f"  [green]✓[/green] langchain-core {langchain_core.__version__}")
    except ImportError:
        console.print("  [yellow]○[/yellow] langchain-core not installed — needed for LangGraph agent scanning")
        warnings += 1

    # Providers
    if info.providers:
        active = [p for p in info.providers if p.is_set]
        inactive = [p for p in info.providers if not p.is_set and p.env_var]
        no_key = [p for p in info.providers if not p.env_var]
        for prov in active:
            console.print(f"  [green]✓[/green] {prov.name} API key set ({prov.env_var})")
        for prov in no_key:
            console.print(f"  [green]✓[/green] {prov.name} detected (no API key needed)")
        if inactive and not active:
            top = inactive[0]
            console.print(f"  [yellow]○[/yellow] {top.name} detected but {top.env_var} not exported")
            console.print(f"       [dim]Run: export {top.env_var}=your-key[/dim]")
            warnings += 1
    else:
        console.print("  [yellow]○[/yellow] No LLM provider detected — `preseal scan` needs your agent's API key")
        console.print("       [dim]preseal audit and preseal scan --demo work without API keys[/dim]")
        warnings += 1

    # Agents
    if info.agents:
        for agent in info.agents[:3]:
            console.print(f"  [green]✓[/green] Agent found: {agent.target} ({agent.framework})")
    else:
        console.print("  [yellow]○[/yellow] No agent files detected in project")
        warnings += 1

    # Attacks
    from .attacks.loader import _builtin_attacks_dir, load_default_attacks
    builtin = _builtin_attacks_dir()
    if builtin.exists():
        attacks = load_default_attacks()
        n_builtin = len(list(builtin.glob("*.yaml"))) if builtin.exists() else 0
        n_custom = len(attacks) - sum(1 for a in attacks if True)  # all are loaded
        console.print(f"  [green]✓[/green] {len(attacks)} attacks loaded ({len(list(builtin.glob('*.yaml')))} built-in YAML files)")
    else:
        console.print("  [red]✗[/red] Built-in attack library not found — reinstall preseal")
        issues += 1

    if info.has_custom_attacks:
        console.print(f"  [green]✓[/green] Custom attacks directory found")

    # Baseline
    if info.has_baseline:
        console.print(f"  [green]✓[/green] Baseline exists (.preseal/baseline.json)")
    else:
        console.print("  [dim]○[/dim] No baseline — run `preseal scan --target ... --save-baseline` to create one")

    # CI
    if info.has_ci_workflow:
        console.print(f"  [green]✓[/green] CI workflow with preseal detected")
    else:
        console.print("  [dim]○[/dim] No CI workflow — see `preseal show-workflow` for a template")

    # Summary
    console.print()
    if issues == 0 and warnings == 0:
        console.print("  [bold green]All checks passed.[/bold green]")
    elif issues == 0:
        console.print(f"  [yellow]{warnings} warning(s)[/yellow] — preseal will work but some features need setup.")
    else:
        console.print(f"  [red]{issues} issue(s)[/red], [yellow]{warnings} warning(s)[/yellow]")

    console.print()


@app.command(name="show-workflow")
def show_workflow() -> None:
    """Print a GitHub Actions workflow template for preseal CI."""
    from pathlib import Path as P
    template = P(__file__).parent.parent.parent / "examples" / "github-workflow.yml"

    if template.exists():
        console.print(template.read_text())
    else:
        console.print(_FALLBACK_WORKFLOW)


_FALLBACK_WORKFLOW = """# .github/workflows/agent-security.yml
name: Agent Security Gate
on: [pull_request]
jobs:
  preseal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install preseal
      - name: Static audit
        run: preseal audit ./src/agent.py
      - name: Adversarial scan
        if: env.OPENAI_API_KEY || env.ANTHROPIC_API_KEY
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: preseal scan --target src.agent:agent
"""


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


def _run_target_scan(target: str, output: str, trials: int, concurrency: int = 5, quick: bool = False) -> None:
    """Run scan against user-specified agent."""
    import importlib
    import time
    from uuid import uuid4
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID

    if ":" not in target:
        console.print("[red]Error: target must be module:object format (e.g., my_agent:agent)[/red]")
        raise typer.Exit(1)

    module_path, obj_name = target.rsplit(":", 1)

    cwd = Path.cwd()
    for _p in [str(cwd), str(cwd / "src")]:
        if _p not in sys.path:
            sys.path.insert(0, _p)

    # Load agent
    console.print(f"[bold]preseal v{__version__}[/bold]")
    console.print(f"[dim]Loading agent: {target}...[/dim]")

    try:
        mod = importlib.import_module(module_path)
        agent_or_factory = getattr(mod, obj_name)
    except (ImportError, AttributeError) as e:
        console.print(f"[red]Error loading {target}: {e}[/red]")
        console.print(f"[dim]Make sure the module is importable from {cwd}[/dim]")
        raise typer.Exit(1)

    if callable(agent_or_factory) and not hasattr(agent_or_factory, "invoke"):
        agent = agent_or_factory()
    else:
        agent = agent_or_factory

    # Verify agent works before running 570 API calls
    from .scanner import verify_agent, run_scan, QUICK_ATTACK_IDS

    console.print("[dim]Verifying agent responds...[/dim]")
    ok, err = verify_agent(agent)
    if not ok:
        console.print(f"[red]Agent verification failed: {err}[/red]")
        console.print("[dim]Check your API key and agent configuration. Run `preseal doctor` for diagnostics.[/dim]")
        raise typer.Exit(1)
    console.print("[green]✓[/green] Agent verified\n")

    # Load attacks
    from .attacks.loader import load_default_attacks
    from .environment import RealEnvironmentManager

    canary_tokens = [f"CANARY_PRESEAL_{uuid4().hex[:12]}" for _ in range(2)]
    env_mgr = RealEnvironmentManager(canary_tokens=canary_tokens)

    all_attacks = load_default_attacks()

    if quick:
        attacks = [a for a in all_attacks if a.id in QUICK_ATTACK_IDS]
        if not attacks:
            attacks = all_attacks[:10]
        mode_label = f"quick scan ({len(attacks)} attacks × {trials} trials)"
    else:
        attacks = all_attacks
        mode_label = f"full scan ({len(attacks)} attacks × {trials} trials)"

    for attack in attacks:
        if not attack.setup_env:
            attack.setup_env = {}
        if attack.category.value == "exfiltration":
            attack.setup_env.setdefault("DB_PASSWORD", canary_tokens[0])
            attack.setup_env.setdefault("AWS_SECRET_ACCESS_KEY", canary_tokens[1])

    total_calls = len(attacks) * trials
    console.print(f"[dim]Running {mode_label} (~{total_calls} LLM calls, concurrency={concurrency})[/dim]\n")

    t_start = time.time()

    # Progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[dim]{task.fields[status]}[/dim]"),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task("Scanning", total=len(attacks), status="")

        def on_progress(attack_idx, total_attacks, attack_name, trial_idx, total_trials):
            progress.update(
                task_id,
                completed=attack_idx - 1 + (trial_idx / total_trials if total_trials else 0),
                description=f"[{attack_idx}/{total_attacks}]",
                status=f"{attack_name} ({trial_idx}/{total_trials})",
            )

        try:
            report = run_scan(
                agent=agent, attacks=attacks, target_name=target, trials=trials,
                concurrency=concurrency,
                canary_tokens=canary_tokens, env_manager=env_mgr,
                on_progress=on_progress,
            )
        finally:
            env_mgr.cleanup()

        progress.update(task_id, completed=len(attacks), status="done")

    elapsed = time.time() - t_start
    console.print(f"[dim]Completed in {elapsed:.0f}s ({elapsed/len(attacks):.1f}s per attack)[/dim]\n")

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
