"""
CLI - ExifTool Commands
"""
import asyncio
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from rich.panel import Panel

from ctf.core.plugin import PluginRegistry

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("read")
def exif_read(
    path: str = typer.Argument(..., help="Path to file"),
):
    """Read all metadata tags from a file."""
    plugin_cls = PluginRegistry.get("forensic", "exiftool_gui")
    if not plugin_cls:
        rprint("[red]exiftool_gui plugin not found.[/red]")
        raise typer.Exit(1)

    plugin = plugin_cls()
    console.print(f"[cyan]Reading metadata[/cyan] from {path} ...")
    result = asyncio.run(plugin.execute(path, mode="read"))

    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    console.print(f"[green]Found {d['total_tags']} tags[/green]\n")

    for group_name, tags in d.get("groups", {}).items():
        table = Table(title=group_name, border_style="cyan", show_header=True)
        table.add_column("Tag", style="yellow", min_width=20)
        table.add_column("Value")
        for tag in tags:
            table.add_row(tag["key"], tag["value"])
        console.print(table)


@app.command("edit")
def exif_edit(
    path: str = typer.Argument(..., help="Path to file"),
    tag: str = typer.Argument(..., help="Tag name (e.g. Author, Title)"),
    value: str = typer.Argument(..., help="New value"),
):
    """Edit a metadata tag in a file."""
    plugin_cls = PluginRegistry.get("forensic", "exiftool_gui")
    if not plugin_cls:
        rprint("[red]exiftool_gui plugin not found.[/red]")
        raise typer.Exit(1)

    plugin = plugin_cls()
    result = asyncio.run(plugin.execute(path, mode="edit", tag_name=tag, tag_value=value))

    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    console.print(f"[green]✓[/green] Set {tag} = {value}")
    console.print(result.data.get("output", ""))


@app.command("delete")
def exif_delete(
    path: str = typer.Argument(..., help="Path to file"),
    tag: str = typer.Argument(..., help="Tag name to delete"),
):
    """Delete a metadata tag from a file."""
    plugin_cls = PluginRegistry.get("forensic", "exiftool_gui")
    if not plugin_cls:
        rprint("[red]exiftool_gui plugin not found.[/red]")
        raise typer.Exit(1)

    plugin = plugin_cls()
    result = asyncio.run(plugin.execute(path, mode="delete", tag_name=tag))

    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    console.print(f"[green]✓[/green] Deleted tag: {tag}")
    console.print(result.data.get("output", ""))
