"""
CLI - Workspace Commands
"""
import asyncio
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from ctf.core import database
from ctf.core.workspace import get_active, set_active

app = typer.Typer(no_args_is_help=True)
console = Console()


def _init():
    asyncio.run(database.init_db())


@app.command("list")
def list_ws():
    """List all workspaces."""
    _init()
    workspaces = asyncio.run(database.list_workspaces())
    active = get_active()

    table = Table(title="Workspaces", border_style="cyan")
    table.add_column("Active", width=6)
    table.add_column("Name", style="cyan")
    table.add_column("Target IP")
    table.add_column("Domain")
    table.add_column("Created")

    for ws in workspaces:
        marker = "✓" if ws["name"] == active else ""
        table.add_row(marker, ws["name"], ws["target_ip"] or "—",
                      ws["target_domain"] or "—", ws["created_at"][:16])
    console.print(table)


@app.command("new")
def new_ws(
    name: str = typer.Argument(..., help="Workspace name"),
    ip: str = typer.Option("", "--ip", help="Target IP"),
    domain: str = typer.Option("", "--domain", "-d", help="Target domain"),
    switch: bool = typer.Option(True, help="Switch to new workspace"),
):
    """Create a new workspace."""
    _init()
    asyncio.run(database.create_workspace(name, ip, domain))
    if switch:
        set_active(name)
        rprint(f"[green]Created and switched to workspace:[/green] {name}")
    else:
        rprint(f"[green]Created workspace:[/green] {name}")


@app.command("switch")
def switch_ws(name: str = typer.Argument(..., help="Workspace name to switch to")):
    """Switch active workspace."""
    _init()
    ws = asyncio.run(database.get_workspace(name))
    if not ws:
        rprint(f"[red]Workspace not found:[/red] {name}")
        raise typer.Exit(1)
    set_active(name)
    rprint(f"[green]Switched to workspace:[/green] {name}")


@app.command("info")
def info_ws(name: str = typer.Option("", help="Workspace name (default: active)")):
    """Show workspace details and results."""
    _init()
    ws_name = name or get_active()
    ws = asyncio.run(database.get_workspace(ws_name))
    if not ws:
        rprint(f"[red]Workspace not found:[/red] {ws_name}")
        raise typer.Exit(1)

    rprint(f"[cyan]Workspace:[/cyan] {ws['name']}")
    rprint(f"  Target IP:  {ws['target_ip'] or '—'}")
    rprint(f"  Domain:     {ws['target_domain'] or '—'}")
    rprint(f"  Notes:      {ws['notes'] or '—'}")

    results = asyncio.run(database.get_results(ws_name))
    flags = asyncio.run(database.get_flags(ws_name))

    rprint(f"\n[cyan]Scan results:[/cyan] {len(results)}")
    for r in results[:5]:
        rprint(f"  [{r['module']}] {r['target']} — {r['created_at'][:16]}")
    if len(results) > 5:
        rprint(f"  … and {len(results)-5} more")

    rprint(f"\n[cyan]Flags:[/cyan] {len(flags)}")
    for f in flags:
        rprint(f"  [yellow]{f['flag']}[/yellow] — {f['description'] or '(no description)'}")


@app.command("flag")
def add_flag(
    flag: str = typer.Argument(..., help="Flag string e.g. FLAG{...}"),
    description: str = typer.Option("", "-d", help="Description"),
):
    """Add a captured flag to the active workspace."""
    _init()
    ws = get_active()
    asyncio.run(database.add_flag(ws, flag, description))
    rprint(f"[green]Flag saved to workspace '{ws}':[/green] {flag}")
