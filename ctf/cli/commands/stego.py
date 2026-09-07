"""
CLI - Steganography Commands
"""
import asyncio
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from ctf.core.plugin import PluginRegistry

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("detect")
def steg_detect(
    path: str = typer.Argument(..., help="Path to image file"),
):
    """Detect steganography in images (LSB, metadata, appended data)."""
    plugin_cls = PluginRegistry.get("stego", "steg_detect")
    if not plugin_cls:
        rprint("[red]steg_detect plugin not found.[/red]")
        raise typer.Exit(1)

    plugin = plugin_cls()
    console.print(f"[cyan]Analyzing[/cyan] {path} ...")
    result = asyncio.run(plugin.execute(path))

    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    table = Table(border_style="cyan", show_header=False)
    table.add_column("Field", style="dim", width=16)
    table.add_column("Value")
    table.add_row("File", path)
    table.add_row("Type", d["file_type"])
    table.add_row("Size", f"{d['file_size']:,} bytes")
    table.add_row("Entropy", str(d["entropy"]))
    table.add_row("Findings", str(d["finding_count"]))
    console.print(table)

    if d.get("findings"):
        console.print()
        for f in d["findings"]:
            severity = f.get("severity", "info")
            color = {"high": "red", "medium": "yellow"}.get(severity, "dim")
            console.print(f"  [{color}]▸ {f['type']}[/{color}]: {f['detail']}")
    else:
        console.print("[green]No steganography indicators found.[/green]")
