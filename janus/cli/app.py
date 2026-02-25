from __future__ import annotations

import asyncio

import click
from rich.console import Console

from janus import __version__
from janus.cli.demo import DEMOS
from janus.cli.formatters import print_agent_table, print_trace_table
from janus.forensics.explainer import TraceExplainer
from janus.forensics.recorder import BlackBoxRecorder
from janus.identity.agent import AgentIdentity, AgentRole, ToolPermission
from janus.identity.registry import AgentRegistry
from janus.storage.database import DatabaseManager

console = Console()


async def _get_db(db_path: str = "janus.db") -> DatabaseManager:
    db = DatabaseManager(db_path)
    await db.connect()
    await db.apply_migrations()
    return db


@click.group()
@click.version_option(version=__version__, prog_name="janus")
def main() -> None:
    """Janus -- Autonomous Security Layer for AI Agents."""


@main.command()
@click.option("--id", "agent_id", required=True, help="Unique agent ID")
@click.option("--name", required=True, help="Agent display name")
@click.option(
    "--role",
    required=True,
    type=click.Choice([r.value for r in AgentRole], case_sensitive=False),
    help="Agent role",
)
@click.option(
    "--permissions", default="",
    help="Comma-separated tool patterns (e.g. 'read_*,search_*')",
)
@click.option("--db", "db_path", default="janus.db", help="Database path")
def register(agent_id: str, name: str, role: str, permissions: str, db_path: str) -> None:
    """Register a new agent identity."""

    async def _run() -> None:
        db = await _get_db(db_path)
        registry = AgentRegistry(db)

        perms = []
        if permissions:
            for p in permissions.split(","):
                perms.append(ToolPermission(tool_pattern=p.strip()))

        agent = AgentIdentity(
            agent_id=agent_id,
            name=name,
            role=AgentRole(role),
            permissions=perms,
        )

        try:
            await registry.register_agent(agent)
            console.print(
                f"[green]Registered agent '{agent_id}' ({name})"
                f" with role '{role}'[/green]"
            )
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        finally:
            await db.close()

    asyncio.run(_run())


@main.command("list-agents")
@click.option("--role", default=None, help="Filter by role")
@click.option("--db", "db_path", default="janus.db", help="Database path")
def list_agents(role: str | None, db_path: str) -> None:
    """List all registered agents."""

    async def _run() -> None:
        db = await _get_db(db_path)
        registry = AgentRegistry(db)

        agent_role = AgentRole(role) if role else None
        agents = await registry.list_agents(agent_role)

        if not agents:
            console.print("[dim]No agents registered.[/dim]")
        else:
            rows = []
            for a in agents:
                patterns = ", ".join(p.tool_pattern for p in a.permissions)
                rows.append({
                    "id": a.agent_id,
                    "name": a.name,
                    "role": a.role.value,
                    "locked": "Yes" if a.is_locked else "No",
                    "permissions": patterns,
                })
            print_agent_table(rows)

        await db.close()

    asyncio.run(_run())


@main.command()
@click.argument("agent_id")
@click.option("--reason", required=True, help="Reason for locking")
@click.option("--db", "db_path", default="janus.db", help="Database path")
def lock(agent_id: str, reason: str, db_path: str) -> None:
    """Lock an agent."""

    async def _run() -> None:
        db = await _get_db(db_path)
        registry = AgentRegistry(db)
        try:
            await registry.lock_agent(agent_id, reason)
            console.print(f"[red]Agent '{agent_id}' locked: {reason}[/red]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        finally:
            await db.close()

    asyncio.run(_run())


@main.command()
@click.argument("agent_id")
@click.option("--db", "db_path", default="janus.db", help="Database path")
def unlock(agent_id: str, db_path: str) -> None:
    """Unlock an agent."""

    async def _run() -> None:
        db = await _get_db(db_path)
        registry = AgentRegistry(db)
        try:
            await registry.unlock_agent(agent_id)
            console.print(f"[green]Agent '{agent_id}' unlocked.[/green]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        finally:
            await db.close()

    asyncio.run(_run())


@main.command()
@click.option("--session", default=None, help="Filter by session ID")
@click.option(
    "--verdict", default=None,
    help="Filter by verdict (allow/block/challenge/sandbox/pause)",
)
@click.option("--limit", default=20, help="Max traces to show")
@click.option("--db", "db_path", default="janus.db", help="Database path")
def traces(session: str | None, verdict: str | None, limit: int, db_path: str) -> None:
    """Query security traces."""

    async def _run() -> None:
        db = await _get_db(db_path)
        recorder = BlackBoxRecorder(db, TraceExplainer())

        if session:
            trace_list = await recorder.get_traces_by_session(session)
        elif verdict:
            trace_list = await recorder.get_traces_by_verdict(verdict, limit=limit)
        else:
            trace_list = await recorder.get_recent_traces(limit=limit)

        if not trace_list:
            console.print("[dim]No traces found.[/dim]")
        else:
            rows = []
            for t in trace_list:
                rows.append({
                    "timestamp": t.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "agent": t.agent_id,
                    "tool": t.tool_name,
                    "verdict": t.verdict,
                    "risk": f"{t.risk_score:.1f}",
                    "explanation": t.explanation,
                })
            print_trace_table(rows)

        await db.close()

    asyncio.run(_run())


@main.command()
@click.argument("scenario", type=click.Choice(list(DEMOS.keys())))
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
def demo(scenario: str, verbose: bool) -> None:
    """Run a built-in demo scenario."""
    name, func = DEMOS[scenario]
    console.print(f"\n[bold]Running demo: {name}[/bold]\n")
    asyncio.run(func(verbose=verbose))


@main.command()
@click.option("--non-interactive", "-y", is_flag=True, help="Accept defaults without prompts")
def init(non_interactive: bool) -> None:
    """Generate a janus.toml configuration file."""
    from janus.cli.init import run_init

    run_init(non_interactive=non_interactive)


@main.command(hidden=True)
@click.option("--tier", default="pro", type=click.Choice(["pro", "free"]), help="License tier")
@click.option("--customer", default="", help="Customer identifier")
@click.option("--days", default=365, help="Expiry in days")
def keygen(tier: str, customer: str, days: int) -> None:
    """Generate a signed license key (requires JANUS_SIGNING_KEY)."""
    import os

    signing_key = os.environ.get("JANUS_SIGNING_KEY")
    if not signing_key:
        console.print("[red]Error: JANUS_SIGNING_KEY environment variable required[/red]")
        raise SystemExit(1)

    from janus.licensing import generate_license

    key = generate_license(
        tier=tier,
        customer_id=customer,
        expiry_days=days,
        signing_key=signing_key.encode(),
    )
    console.print(f"[green]{key}[/green]")


@main.command("export")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "jsonl", "csv"]))
@click.option("--verdict", default=None, help="Filter by verdict")
@click.option("--agent", "agent_id", default=None, help="Filter by agent ID")
@click.option("--session", "session_id", default=None, help="Filter by session ID")
@click.option("--from", "date_from", default=None, help="Start date (ISO format)")
@click.option("--to", "date_to", default=None, help="End date (ISO format)")
@click.option("--min-risk", default=None, type=float, help="Minimum risk score")
@click.option("--limit", default=10000, help="Max traces to export")
@click.option("-o", "--output", default=None, help="Output file (default: stdout)")
@click.option("--db", "db_path", default="janus.db", help="Database path")
def export_traces(
    fmt: str,
    verdict: str | None,
    agent_id: str | None,
    session_id: str | None,
    date_from: str | None,
    date_to: str | None,
    min_risk: float | None,
    limit: int,
    output: str | None,
    db_path: str,
) -> None:
    """Export security traces as CSV, JSON, or JSONL."""
    from janus.forensics.exporter import TraceExporter

    async def _run() -> None:
        db = await _get_db(db_path)
        exporter = TraceExporter(db)
        traces = await exporter.query_traces(
            date_from=date_from,
            date_to=date_to,
            verdict=verdict,
            agent_id=agent_id,
            session_id=session_id,
            min_risk=min_risk,
            limit=limit,
        )

        if fmt == "csv":
            content = exporter.to_csv(traces)
        elif fmt == "jsonl":
            content = exporter.to_jsonl(traces)
        else:
            content = exporter.to_json(traces)

        if output:
            from pathlib import Path
            Path(output).write_text(content)
            console.print(f"[green]Exported {len(traces)} traces to {output}[/green]")
        else:
            console.print(content)

        await db.close()

    asyncio.run(_run())


@main.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, help="Port to bind to")
@click.option("--config", "config_path", default=None, help="Path to janus.toml")
def serve(host: str, port: int, config_path: str | None) -> None:
    """Launch the Janus web dashboard."""
    from pathlib import Path

    from janus.web.app import run_server

    # Auto-discover janus.toml
    if config_path is None:
        default = Path.cwd() / "janus.toml"
        if default.exists():
            config_path = str(default)
            console.print(f"[dim]Loading config from {config_path}[/dim]")

    if config_path:
        import os

        from janus.config import JanusConfig

        os.environ["JANUS_CONFIG_PATH"] = config_path
        config = JanusConfig.from_toml(config_path)
        if not os.environ.get("JANUS_DB_PATH"):
            os.environ["JANUS_DB_PATH"] = config.database_path

    console.print(
        f"[bold green]Janus Dashboard[/bold green] starting at "
        f"http://{host}:{port}"
    )
    run_server(host=host, port=port)


if __name__ == "__main__":
    main()
