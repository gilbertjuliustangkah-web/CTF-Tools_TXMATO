"""
CLI - Recon Commands
"""
import asyncio
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from ctf.core.plugin import PluginRegistry
from ctf.core.workspace import get_active
from ctf.core import database

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("scan")
def port_scan(
    target: str = typer.Argument(..., help="IP or hostname to scan"),
    ports: str = typer.Option("common", "-p", "--ports", help="Ports to scan (common | all | 80,443,8080)"),
    save: bool = typer.Option(True, help="Save results to workspace"),
):
    """Scan open ports on a target."""
    plugin_cls = PluginRegistry.get("recon", "port_scan")
    if not plugin_cls:
        rprint("[red]Port scanner plugin not found.[/red]")
        raise typer.Exit(1)

    plugin = plugin_cls()
    console.print(f"[cyan]Scanning[/cyan] {target} …")

    result = asyncio.run(plugin.execute(target, ports=ports))

    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    ports_data = result.data.get("ports", [])
    method = result.data.get("method", "?")

    table = Table(title=f"Port Scan — {target} (via {method})", border_style="cyan")
    table.add_column("Port", style="yellow", width=8)
    table.add_column("Protocol", width=10)
    table.add_column("State", style="green", width=8)
    table.add_column("Service", style="cyan", width=14)
    table.add_column("Version")

    for p in ports_data:
        table.add_row(
            str(p["port"]),
            p.get("protocol", "tcp"),
            p["state"],
            p["service"],
            p.get("version", ""),
        )

    if ports_data:
        console.print(table)
    else:
        rprint("[yellow]No open ports found.[/yellow]")

    if save:
        ws = get_active()
        asyncio.run(database.init_db())
        rid = asyncio.run(database.save_result(ws, "recon", target, result.to_dict()))
        rprint(f"[dim]Saved to workspace '{ws}' (id={rid})[/dim]")
