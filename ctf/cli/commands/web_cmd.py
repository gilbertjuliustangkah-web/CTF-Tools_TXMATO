"""
CLI - Web Dashboard Command
"""
import os

import typer
from rich import print as rprint

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
