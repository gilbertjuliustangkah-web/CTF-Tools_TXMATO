"""
CTF Toolkit - CLI Entry Point
"""
import asyncio
import sys

import typer
from rich.console import Console
from rich.panel import Panel

# Force UTF-8 output so Unicode symbols (✓, —, …) render on Windows consoles
# that otherwise default to cp1252/cp437, which causes UnicodeEncodeError.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Import all plugins so they get registered
import ctf.modules.recon.port_scan
import ctf.modules.crypto.encoder
import ctf.modules.forensic.file_inspect

from ctf.cli.commands import recon, crypto, forensic, workspace, web_cmd, tools

app = typer.Typer(
    name="ctf",
    help="CTF Toolkit — unified CLI + web dashboard",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
console = Console()

app.add_typer(recon.app,     name="recon",     help="Recon tools (port scan, headers, …)")
app.add_typer(crypto.app,    name="crypto",    help="Crypto tools (encode, decode, hash, …)")
app.add_typer(forensic.app,  name="forensic",  help="Forensic tools (file inspect, strings, …)")
app.add_typer(workspace.app, name="workspace", help="Manage CTF workspaces")
app.add_typer(tools.app,     name="tools",     help="Tool catalog & manager (like ctf-tools)")
app.add_typer(web_cmd.app,   name="web",       help="Start the local web dashboard")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        console.print(Panel(
            "[bold cyan]CTF Toolkit[/bold cyan] v0.1.0\n"
            "Run [bold]ctf --help[/bold] to see all commands.",
            border_style="cyan"
        ))


if __name__ == "__main__":
    app()
