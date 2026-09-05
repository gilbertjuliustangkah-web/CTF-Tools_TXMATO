"""
CLI - Forensic Commands
"""
import asyncio
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from ctf.core.plugin import PluginRegistry

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("inspect")
def inspect_file(
    path: str = typer.Argument(..., help="Path to file"),
    strings: bool = typer.Option(False, "--strings", "-s", help="Show extracted strings"),
):
    """Inspect a file: type, entropy, metadata, hex preview."""
    plugin_cls = PluginRegistry.get("forensic", "file_inspect")
    if not plugin_cls:
        rprint("[red]File inspect plugin not found.[/red]")
        raise typer.Exit(1)

    plugin = plugin_cls()
    console.print(f"[cyan]Inspecting[/cyan] {path} …")
    result = asyncio.run(plugin.execute(path))

    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data

    table = Table(border_style="cyan", show_header=False)
    table.add_column("Field", style="dim", width=18)
    table.add_column("Value")
    table.add_row("File", d["path"])
    table.add_row("Type", d["file_type"])
    table.add_row("Size", f"{d['size_human']} ({d['size_bytes']} bytes)")
    table.add_row("Entropy", f"{d['entropy']} / 8.0")
    table.add_row("Hex preview", d["hex_preview"][:48] + "…")
    console.print(table)

    if "exiftool" in d:
        console.print(Panel(d["exiftool"][:600], title="[cyan]Exiftool metadata[/cyan]", border_style="dim"))

    if strings:
        s = d.get("strings", [])
        console.print(f"\n[cyan]Strings ({len(s)} found):[/cyan]")
        for line in s[:50]:
            rprint(f"  {line}")
        if len(s) > 50:
            rprint(f"  [dim]… and {len(s)-50} more[/dim]")
