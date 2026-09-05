"""
CLI - Crypto Commands
"""
import asyncio
import typer
from rich.console import Console
from rich import print as rprint
from rich.panel import Panel

from ctf.core.plugin import PluginRegistry

app = typer.Typer(no_args_is_help=True)
console = Console()

MODES = ["detect", "b64enc", "b64dec", "hexenc", "hexdec",
         "binenc", "bindec", "urlenc", "urldec", "rot13"]


@app.command("encode")
def encode(
    data: str = typer.Argument(..., help="String to encode/decode"),
    mode: str = typer.Option("detect", "-m", help=f"Mode: {' | '.join(MODES)}"),
):
    """Encode / decode a string (base64, hex, binary, URL, ROT13, auto-detect)."""
    plugin_cls = PluginRegistry.get("crypto", "encode")
    if not plugin_cls:
        rprint("[red]Encode plugin not found.[/red]")
        raise typer.Exit(1)

    plugin = plugin_cls()
    result = asyncio.run(plugin.execute(data, mode=mode))

    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    if "result" in d:
        console.print(Panel(d["result"], title=f"[cyan]{d['mode']}[/cyan]", border_style="cyan"))
    elif "detections" in d:
        det = d["detections"]
        if not det:
            rprint("[yellow]No encoding detected.[/yellow]")
        else:
            for enc, val in det.items():
                if enc == "hash_hints":
                    if val:
                        rprint(f"[yellow]Hash type hints:[/yellow] {', '.join(val)}")
                else:
                    console.print(Panel(str(val), title=f"[cyan]{enc}[/cyan]", border_style="green"))
