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
    console.print(f"[cyan]Inspecting[/cyan] {path} ...")
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
    table.add_row("Hex preview", d["hex_preview"][:48] + "...")
    console.print(table)

    if "exiftool" in d:
        console.print(Panel(d["exiftool"][:600], title="[cyan]Exiftool metadata[/cyan]", border_style="dim"))

    if strings:
        s = d.get("strings", [])
        console.print(f"\n[cyan]Strings ({len(s)} found):[/cyan]")
        for line in s[:50]:
            rprint(f"  {line}")
        if len(s) > 50:
            rprint(f"  [dim]... and {len(s)-50} more[/dim]")


@app.command("binwalk")
def binwalk_scan(
    path: str = typer.Argument(..., help="Path to file"),
    mode: str = typer.Option("signature", help="Mode: signature | extract | entropy"),
):
    """Scan files with binwalk (magic signatures, entropy, extraction)."""
    plugin_cls = PluginRegistry.get("forensic", "binwalk_scan")
    if not plugin_cls:
        rprint("[red]binwalk plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(path, mode=mode))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    console.print(f"[cyan]Found {d['count']} signatures:[/cyan]")
    for sig in d["signatures"]:
        console.print(f"  {sig['hex_offset']:>12s}  {sig['description']}")
    if not d["signatures"]:
        rprint("[yellow]No signatures found.[/yellow]")


@app.command("strings")
def strings_extract(
    path: str = typer.Argument(..., help="Path to file"),
    min_len: int = typer.Option(4, "-l", "--min-length", help="Minimum string length"),
):
    """Extract printable strings (ASCII, UTF-16) from a file."""
    plugin_cls = PluginRegistry.get("forensic", "strings_extract")
    if not plugin_cls:
        rprint("[red]strings_extract plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(path, min_length=min_len))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    console.print(f"[cyan]Found {d['total_count']} strings ({d['file_size']:,} bytes)[/cyan]\n")
    for enc_type, strings in d["strings"].items():
        console.print(f"[yellow]{enc_type.upper()} ({len(strings)}):[/yellow]")
        for s in strings[:50]:
            console.print(f"  {s}")
        if len(strings) > 50:
            rprint(f"  [dim]... and {len(strings)-50} more[/dim]")


@app.command("hash")
def hash_calc(
    path: str = typer.Argument(..., help="Path to file"),
    algorithms: str = typer.Option("md5,sha1,sha256", "-a", help="Comma-separated hash algorithms"),
):
    """Calculate file hashes (MD5, SHA1, SHA256, SHA512, etc.)."""
    plugin_cls = PluginRegistry.get("forensic", "hash_calc")
    if not plugin_cls:
        rprint("[red]hash_calc plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(path, algorithms=algorithms))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    table = Table(title=f"Hashes - {d['filename']}", border_style="cyan")
    table.add_column("Algorithm", style="yellow")
    table.add_column("Hash")
    for algo, h in d["hashes"].items():
        table.add_row(algo, h)
    console.print(table)


@app.command("hexdump")
def hexdump_cmd(
    path: str = typer.Argument(..., help="Path to file"),
    offset: int = typer.Option(0, help="Start offset"),
    length: int = typer.Option(256, help="Bytes to dump"),
):
    """View hex dump of a file."""
    plugin_cls = PluginRegistry.get("forensic", "hexdump_view")
    if not plugin_cls:
        rprint("[red]hexdump_view plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(path, offset=offset, length=length))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    console.print(f"[cyan]Hex dump[/cyan] offset={d['offset']}, length={d['length']}, total={d['total_size']}\n")
    for line in d["lines"]:
        console.print(f"  {line}")


@app.command("pdf")
def pdf_analyze(
    path: str = typer.Argument(..., help="Path to PDF file"),
):
    """Analyze PDF: metadata, JavaScript, embedded files, suspicious patterns."""
    plugin_cls = PluginRegistry.get("forensic", "pdf_analyze")
    if not plugin_cls:
        rprint("[red]pdf_analyze plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(path))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    table = Table(title="PDF Analysis", border_style="cyan")
    table.add_column("Field", style="dim", width=20)
    table.add_column("Value")
    table.add_row("PDF Version", d["pdf_version"])
    table.add_row("File Size", f"{d['file_size']:,} bytes")
    table.add_row("Objects", str(len(d["objects"])))
    table.add_row("Pages", str(d["pages"]))
    table.add_row("JavaScript", "YES" if d["has_javascript"] else "No")
    table.add_row("Embedded Files", "YES" if d["has_embedded_files"] else "No")
    table.add_row("Launch Actions", "YES" if d["has_launch_action"] else "No")
    for k, v in d.get("metadata", {}).items():
        table.add_row(f"Meta: {k}", v)
    console.print(table)

    for w in d.get("warnings", []):
        rprint(f"  [red]! {w}[/red]")
