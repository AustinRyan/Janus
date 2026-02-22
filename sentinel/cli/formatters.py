from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinel.core.decision import SecurityVerdict, Verdict

console = Console()

VERDICT_COLORS = {
    Verdict.ALLOW: "green",
    Verdict.BLOCK: "red",
    Verdict.CHALLENGE: "yellow",
    Verdict.SANDBOX: "cyan",
    Verdict.PAUSE: "magenta",
}


def format_verdict(verdict: SecurityVerdict, step_label: str = "") -> None:
    """Print a formatted verdict to the console."""
    color = VERDICT_COLORS.get(verdict.verdict, "white")
    header = f"[bold {color}]{verdict.verdict.value.upper()}[/bold {color}]"
    if step_label:
        header = f"{step_label} → {header}"

    lines = [
        f"  Risk Score:  {verdict.risk_score:.1f}/100",
        f"  Risk Delta:  +{verdict.risk_delta:.1f}",
    ]

    if verdict.drift_score > 0:
        lines.append(f"  Drift Score: {verdict.drift_score:.2f}")

    if verdict.reasons:
        lines.append(f"  Reasons:     {'; '.join(verdict.reasons[:3])}")

    if verdict.itdr_signals:
        lines.append(f"  ITDR:        {'; '.join(verdict.itdr_signals[:3])}")

    if verdict.recommended_action:
        lines.append(f"  Action:      {verdict.recommended_action}")

    console.print(Panel("\n".join(lines), title=header, border_style=color))


def format_risk_bar(score: float, width: int = 40) -> str:
    """Create an ASCII risk score bar."""
    filled = int(score / 100 * width)
    empty = width - filled

    if score < 40:
        color = "green"
    elif score < 60:
        color = "yellow"
    elif score < 80:
        color = "dark_orange"
    else:
        color = "red"

    return f"[{color}]{'█' * filled}{'░' * empty}[/{color}] {score:.1f}/100"


def print_agent_table(agents: list[dict[str, str]]) -> None:
    """Print a table of registered agents."""
    table = Table(title="Registered Agents")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Role", style="green")
    table.add_column("Locked", style="red")
    table.add_column("Permissions")

    for agent in agents:
        table.add_row(
            agent["id"],
            agent["name"],
            agent["role"],
            agent.get("locked", "No"),
            agent.get("permissions", ""),
        )

    console.print(table)


def print_trace_table(traces: list[dict[str, str]]) -> None:
    """Print a table of security traces."""
    table = Table(title="Security Traces")
    table.add_column("Time", style="dim")
    table.add_column("Agent", style="cyan")
    table.add_column("Tool", style="white")
    table.add_column("Verdict", style="bold")
    table.add_column("Risk", justify="right")
    table.add_column("Explanation")

    for trace in traces:
        verdict_color = {
            "allow": "green",
            "block": "red",
            "challenge": "yellow",
            "sandbox": "cyan",
            "pause": "magenta",
        }.get(trace.get("verdict", ""), "white")

        table.add_row(
            trace.get("timestamp", ""),
            trace.get("agent", ""),
            trace.get("tool", ""),
            f"[{verdict_color}]{trace.get('verdict', '').upper()}[/{verdict_color}]",
            trace.get("risk", ""),
            trace.get("explanation", "")[:80],
        )

    console.print(table)
