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
    console.print(f"[cyan]Scanning[/cyan] {target} ...")

    result = asyncio.run(plugin.execute(target, ports=ports))

    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    ports_data = result.data.get("ports", [])
    method = result.data.get("method", "?")

    table = Table(title=f"Port Scan - {target} (via {method})", border_style="cyan")
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


@app.command("dns")
def dns_lookup(
    target: str = typer.Argument(..., help="Domain to lookup"),
    record_type: str = typer.Option("A", "-t", "--type", help="Record type (A, AAAA, MX, NS, TXT, SOA)"),
):
    """DNS record lookup for a domain."""
    plugin_cls = PluginRegistry.get("recon", "dns_lookup")
    if not plugin_cls:
        rprint("[red]dns_lookup plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(target, type=record_type))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    table = Table(title=f"DNS Lookup - {target}", border_style="cyan")
    table.add_column("Type", style="yellow", width=8)
    table.add_column("Record")
    for rec in d.get("records", []):
        table.add_row(record_type, rec)
    console.print(table)


@app.command("whois")
def whois_lookup(
    target: str = typer.Argument(..., help="Domain to lookup"),
):
    """WHOIS domain registration lookup."""
    plugin_cls = PluginRegistry.get("recon", "whois_lookup")
    if not plugin_cls:
        rprint("[red]whois_lookup plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(target))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    fields = d.get("fields", {})
    if fields:
        table = Table(title=f"WHOIS - {target}", border_style="cyan")
        table.add_column("Field", style="dim", width=22)
        table.add_column("Value")
        for k, v in fields.items():
            if isinstance(v, list):
                v = ", ".join(v)
            table.add_row(k, str(v))
        console.print(table)
    else:
        console.print(Panel(d.get("raw", "No data")[:800], title=f"WHOIS - {target}"))


@app.command("ssl")
def ssl_check(
    target: str = typer.Argument(..., help="Domain or host:port"),
    port: int = typer.Option(443, help="Port"),
):
    """SSL/TLS certificate analysis."""
    plugin_cls = PluginRegistry.get("recon", "ssl_check")
    if not plugin_cls:
        rprint("[red]ssl_check plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(target, port=port))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    table = Table(title=f"SSL Certificate - {target}", border_style="cyan")
    table.add_column("Field", style="dim", width=22)
    table.add_column("Value")
    for k in ["subject", "issuer", "not_before", "not_after", "days_until_expiry", "san", "serial"]:
        if k in d:
            val = d[k]
            if isinstance(val, list):
                val = ", ".join(val)
            table.add_row(k, str(val))
    console.print(table)

    for w in d.get("warnings", []):
        rprint(f"  [yellow]! {w}[/yellow]")
