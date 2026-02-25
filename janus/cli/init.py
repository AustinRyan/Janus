"""janus init — generate a janus.toml configuration file."""
from __future__ import annotations

from pathlib import Path

TEMPLATE = """\
[janus]
# database_path = "~/.janus/janus.db"
log_level = "INFO"
# license_key = ""

[risk]
lock_threshold = 80.0
sandbox_threshold = 60.0
elevated_logging_threshold = 40.0
decay_rate_per_minute = 2.0
decay_idle_threshold_minutes = 5.0

[circuit_breaker]
failure_threshold = 5
recovery_timeout_seconds = 30.0
success_threshold = 3

[drift]
threshold = 0.6
max_risk_contribution = 40.0

[guardian_model]
model = "claude-haiku-4-5-20251001"
max_tokens = 512
temperature = 0.0
timeout_seconds = 5.0

# [exporters]
# webhook_url = ""
# json_log_path = ""
# prometheus_enabled = false
# otel_enabled = false
# otel_service_name = "janus"

# [[agents]]
# agent_id = "my-agent"
# name = "My Agent"
# role = "research"
# permissions = ["read_*", "search_*"]
"""


def run_init(non_interactive: bool = False) -> Path:
    """Generate janus.toml in the current directory.

    Returns the path to the generated file.
    """
    from rich.console import Console

    console = Console()
    output = Path.cwd() / "janus.toml"

    if output.exists() and not non_interactive:
        from rich.prompt import Confirm

        if not Confirm.ask(f"[yellow]{output} already exists. Overwrite?[/yellow]"):
            console.print("[dim]Aborted.[/dim]")
            return output

    output.write_text(TEMPLATE)
    console.print(f"[green]Created {output}[/green]")
    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print("  1. Edit janus.toml to configure thresholds and add your license key")
    console.print("  2. Run [cyan]janus serve[/cyan] to start the dashboard")
    console.print("  3. Set [cyan]ANTHROPIC_API_KEY[/cyan] for LLM-powered security checks")
    return output
