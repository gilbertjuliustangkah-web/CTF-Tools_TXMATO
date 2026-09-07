"""
CLI - Web Commands (dashboard server + HTTP recon tools)
"""
import asyncio
import os

import typer
from rich import print as rprint
from rich.panel import Panel
from rich.table import Table

from ctf.core.plugin import PluginRegistry

app = typer.Typer(no_args_is_help=True)


@app.command("start")
def start(
    host: str = typer.Option("127.0.0.1", help="Host to bind"),
    port: int = typer.Option(8080, "-p", "--port", help="Port"),
    reload: bool = typer.Option(False, help="Auto-reload on file change (dev mode)"),
):
    """Start the local web dashboard."""
    import uvicorn

    loopback = host in ("127.0.0.1", "localhost", "::1", "")

    # Communicate bind info to the FastAPI app (read at import time).
    os.environ["CTF_HOST"] = host
    os.environ["CTF_PORT"] = str(port)

    from ctf.api import security

    auth_required = security.require_auth_for(host)
    token = security.get_token()

    url = f"http://{host}:{port}"
    rprint(f"[cyan]Starting CTF Toolkit web dashboard[/cyan] → {url}")

    if auth_required:
        rprint(f"[yellow]Auth is enabled (bound beyond localhost). Access token:[/yellow] {token}")
        rprint("[dim]Login at /login with the token above.[/dim]")
    else:
        rprint("[dim]Localhost only — no token required. CSRF protection is enabled.[/dim]")

    if reload and loopback is False:
        rprint("[dim]Note: --reload with a LAN host is fine but unsupported by some setups.[/dim]")

    uvicorn.run(
        "ctf.api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="warning",
    )


def _console():
    from rich.console import Console
    return Console()


@app.command("headers")
def http_headers(url: str = typer.Argument(..., help="Target URL (http(s):// or bare host)")):
    """Fetch HTTP headers, status code, and redirect chain."""
    plugin_cls = PluginRegistry.get("web", "http_headers")
    if not plugin_cls:
        rprint("[red]http_headers plugin not found.[/red]")
        raise typer.Exit(1)

    console = _console()
    plugin = plugin_cls()
    console.print(f"[cyan]Fetching headers for[/cyan] {url} …")
    result = asyncio.run(plugin.execute(url))

    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    console.print(f"URL: [yellow]{d['url']}[/yellow]  ·  status [bold]{d['status']}[/bold]  ·  "
                  f"redirects: {d['redirections']}  ·  body: {d['body_size']} B")
    table = Table(border_style="cyan")
    table.add_column("Header", style="dim", width=24)
    table.add_column("Value")
    for k, v in d["headers"]:
        table.add_row(k, v)
    console.print(table)
    if d["cookies"]:
        console.print(f"[cyan]Cookies set:[/cyan] {', '.join(d['cookies'])}")


@app.command("robots")
def robots_txt(url: str = typer.Argument(..., help="Target URL (scheme/domain)")):
    """Fetch and parse /robots.txt for interesting paths."""
    plugin_cls = PluginRegistry.get("web", "robots_txt")
    if not plugin_cls:
        rprint("[red]robots_txt plugin not found.[/red]")
        raise typer.Exit(1)

    console = _console()
    plugin = plugin_cls()
    console.print(f"[cyan]Fetching robots.txt for[/cyan] {url} …")
    result = asyncio.run(plugin.execute(url))

    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    console.print(f"URL: [yellow]{d['url']}[/yellow]  ·  status [bold]{d['status']}[/bold]")
    for agent, allows, disallows, other in d["entries"]:
        console.print(f"[cyan]User-agent:[/cyan] {agent}")
        for p in allows:
            console.print(f"  ✓ Allow:    {p}")
        for p in disallows:
            console.print(f"  ✗ Disallow: {p}")
        for line in other:
            console.print(f"  · {line}")
    for s in d["sitemaps"]:
        console.print(f"[dim]Sitemap:[/dim] {s}")
    paths = d["interesting_paths"]
    if paths:
        console.print(f"\n[yellow]Interesting paths:[/yellow] {', '.join(paths)}")


@app.command("jwt")
def jwt_decode(token: str = typer.Argument(..., help="JWT token to decode")):
    """Decode and analyze a JWT token."""
    plugin_cls = PluginRegistry.get("web", "jwt_decode")
    if not plugin_cls:
        rprint("[red]jwt_decode plugin not found.[/red]")
        raise typer.Exit(1)

    console = _console()
    result = asyncio.run(plugin_cls().execute(token))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    console.print(Panel(d["header"], title="Header", border_style="cyan"))
    console.print(Panel(d["payload"], title="Payload", border_style="green"))
    for w in d.get("warnings", []):
        rprint(f"  [yellow]! {w}[/yellow]")


@app.command("cookies")
def cookie_inspect(cookie_string: str = typer.Argument(..., help="Cookie string to parse")):
    """Parse and analyze HTTP cookies for security flags."""
    plugin_cls = PluginRegistry.get("web", "cookie_inspect")
    if not plugin_cls:
        rprint("[red]cookie_inspect plugin not found.[/red]")
        raise typer.Exit(1)

    console = _console()
    result = asyncio.run(plugin_cls().execute(cookie_string))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    console.print(f"[cyan]Parsed {d['count']} cookies:[/cyan]")
    for cookie in d["cookies"]:
        flags = []
        if cookie["secure"]:
            flags.append("Secure")
        if cookie["httponly"]:
            flags.append("HttpOnly")
        console.print(f"  [yellow]{cookie['name']}[/yellow] = {cookie['value'][:60]}  [dim]({', '.join(flags) or 'no flags'})[/dim]")

    for note in d.get("security_notes", []):
        rprint(f"  [red]! {note}[/red]")


@app.command("dir")
def dir_enum(
    url: str = typer.Argument(..., help="Target URL (e.g. http://example.com)"),
):
    """Enumerate web directories and files."""
    plugin_cls = PluginRegistry.get("web", "dir_enum")
    if not plugin_cls:
        rprint("[red]dir_enum plugin not found.[/red]")
        raise typer.Exit(1)

    console = _console()
    console.print(f"[cyan]Enumerating[/cyan] {url} ...")
    result = asyncio.run(plugin_cls().execute(url))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    console.print(f"[cyan]Method:[/cyan] {d.get('method', '?')}  ·  checked {d.get('total_checked', '?')} paths, found {d['total_found']}")

    for entry in d.get("found", []):
        status = entry.get("status", "")
        path = entry.get("path", "")
        try:
            status_color = "green" if int(status) < 400 else "yellow"
        except (ValueError, TypeError):
            status_color = "yellow"
        console.print(f"  [{status_color}]{status}[/{status_color}]  {path}")


@app.command("dns")
def dns_lookup(domain: str = typer.Argument(..., help="Domain to lookup")):
    """DNS record lookup for a domain."""
    plugin_cls = PluginRegistry.get("recon", "dns_lookup")
    if not plugin_cls:
        rprint("[red]dns_lookup plugin not found.[/red]")
        raise typer.Exit(1)

    console = _console()
    result = asyncio.run(plugin_cls().execute(domain))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    console.print(f"[cyan]DNS records for[/cyan] {domain}:")
    for rec in d.get("records", []):
        console.print(f"  {rec}")
