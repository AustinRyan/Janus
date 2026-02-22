from __future__ import annotations

import asyncio

import click
from rich.console import Console

from sentinel.cli.demo import DEMOS
from sentinel.cli.formatters import print_agent_table, print_trace_table
from sentinel.forensics.explainer import TraceExplainer
from sentinel.forensics.recorder import BlackBoxRecorder
from sentinel.identity.agent import AgentIdentity, AgentRole, ToolPermission
from sentinel.identity.registry import AgentRegistry
from sentinel.storage.database import DatabaseManager

console = Console()


async def _get_db(db_path: str = "sentinel.db") -> DatabaseManager:
    db = DatabaseManager(db_path)
    await db.connect()
    await db.apply_migrations()
    return db


@click.group()
@click.version_option(version="0.1.0", prog_name="sentinel")
def main() -> None:
    """Sentinel -- Autonomous Security Layer for AI Agents."""


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
@click.option("--db", "db_path", default="sentinel.db", help="Database path")
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
@click.option("--db", "db_path", default="sentinel.db", help="Database path")
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
@click.option("--db", "db_path", default="sentinel.db", help="Database path")
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
@click.option("--db", "db_path", default="sentinel.db", help="Database path")
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
@click.option("--db", "db_path", default="sentinel.db", help="Database path")
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


if __name__ == "__main__":
    main()
