"""
CLI - Pwn Commands (checksec, cyclic patterns)
"""
import asyncio
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from ctf.core.plugin import PluginRegistry

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("checksec")
def checksec_file(path: str = typer.Argument(..., help="Path to ELF binary")):
    """Inspect binary hardening: PIE, NX, RELRO, canary, fortify."""
    plugin_cls = PluginRegistry.get("pwn", "checksec")
    if not plugin_cls:
        rprint("[red]checksec plugin not found.[/red]")
        raise typer.Exit(1)

    plugin = plugin_cls()
    console.print(f"[cyan]Checking[/cyan] {path} …")
    result = asyncio.run(plugin.execute(path))

    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    table = Table(border_style="cyan", show_header=False)
    table.add_column("Property", style="dim", width=18)
    table.add_column("Value")

    table.add_row("Type", f"{d['class']} · {d['type']} · {d['machine']}")
    table.add_row("Entry", d["entry"])
    table.add_row("PIE", _mark(d["pie"]))
    table.add_row("NX", _mark(d["nx"], bad="Disabled"))
    table.add_row("RELRO", _mark(d["relro"], good=("FULL"), bad=("No")))
    table.add_row(
        "Canary",
        _mark("Canary enabled" if d["canary"] == "Yes" else "No canary",
              bad="No canary"),
    )
    table.add_row(
        "FORTIFY",
        _mark("FORTIFY enabled" if d["fortify"] == "Yes" else "No FORTIFY",
              bad="No FORTIFY"),
    )
    table.add_row("RPATH/RUNPATH", _mark(d["rpath"], bad="Yes"))
    console.print(table)

    for adv in d.get("advice", []):
        console.print(f"  [yellow]▸[/yellow] {adv}")

    console.print(f"[dim]Stripped: {d['stripped']}[/dim]")


def _mark(val: str, good: tuple = (), bad: tuple = ()) -> str:
    def contains(needles, text):
        if isinstance(needles, str):
            return needles in text
        return any(n in text for n in needles)

    if bad and contains(bad, val):
        return f"[red]✗ {val}[/red]"
    if good and contains(good, val):
        return f"[green]✓ {val}[/green]"
    return val


@app.command("cyclic")
def cyclic_gen(
    length: int = typer.Argument(..., help="Pattern length"),
    show: bool = typer.Option(True, help="Print the pattern"),
):
    """Generate a De Bruijn cyclic pattern for buffer-overflow offset finding."""
    plugin_cls = PluginRegistry.get("pwn", "cyclic")
    result = asyncio.run(plugin_cls().execute("generate", mode="generate", length=length))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)
    pattern = result.data["pattern"]
    console.print(f"[green]Generated {length} bytes:[/green]")
    if show:
        console.print(pattern)
    console.print(f"[dim]Save it into a payload, crash the binary, then run: "
                  f"ctf pwn cyclic-find <pattern-from-the-crash>[/dim]")


@app.command("cyclic-find")
def cyclic_find_cmd(
    pattern: str = typer.Argument(..., help="Bytes from the crash (ASCII or 0x hex)"),
):
    """Find the offset of a cyclic subsequence (like pwntools cyclic_find)."""
    plugin_cls = PluginRegistry.get("pwn", "cyclic")
    result = asyncio.run(plugin_cls().execute("find", mode="find", pattern=pattern))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)
    d = result.data
    off = d["offset"]
    console.print(f"[green]Offset:[/green] {off}")
    console.print(f"  [bold cyan]0x{off:08x}[/bold cyan] (LE32 payload bytes: {off.to_bytes(4, 'little').hex()})")
    console.print(f"  [dim]LE64:[/dim] {off.to_bytes(8, 'little').hex()}")
    console.print(f"  [dim]As unsigned 32-bit:[/dim] {off}")


@app.command("rop")
def rop_search(
    path: str = typer.Argument(..., help="Path to binary"),
    search_term: str = typer.Option("", "-s", "--search", help="Specific gadget to search for"),
    max_gadgets: int = typer.Option(50, help="Max gadgets to show"),
):
    """Search for ROP gadgets in binaries."""
    plugin_cls = PluginRegistry.get("pwn", "rop_search")
    if not plugin_cls:
        rprint("[red]rop_search plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(path, search=search_term, max_gadgets=max_gadgets))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    console.print(f"[cyan]Found {d['total_found']} gadgets (showing {max_gadgets})[/cyan]\n")

    table = Table(title="ROP Gadgets", border_style="cyan")
    table.add_column("Address", style="yellow", width=16)
    table.add_column("Gadget")
    for g in d["gadgets"][:max_gadgets]:
        table.add_row(g["address"], g.get("gadget", g.get("opcode", "")))
    console.print(table)

    useful = d.get("useful", {})
    if any(useful.values()):
        console.print(f"\n[cyan]Useful gadgets:[/cyan]")
        for cat, gadgets in useful.items():
            if gadgets:
                console.print(f"  [yellow]{cat}:[/yellow] {', '.join(g['address'] for g in gadgets[:5])}")