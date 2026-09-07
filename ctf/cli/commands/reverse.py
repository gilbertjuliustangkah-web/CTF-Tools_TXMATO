"""
CLI - Reverse Engineering Commands
"""
import asyncio
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from ctf.core.plugin import PluginRegistry

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("info")
def binary_info(
    path: str = typer.Argument(..., help="Path to the binary"),
    segments: bool = typer.Option(False, "--segments", help="Show all program headers"),
    sections: bool = typer.Option(False, "--sections", help="Show all sections"),
    imports: bool = typer.Option(True, help="Show dynamic symbols / imports"),
):
    """Analyze an ELF (or PE/Mach-O) binary: headers, sections, imports."""
    plugin_cls = PluginRegistry.get("reverse", "binary_info")
    if not plugin_cls:
        rprint("[red]binary_info plugin not found.[/red]")
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
    table.add_row("Path", d["path"])
    table.add_row("Type", d.get("format") or d.get("magic", "?"))
    if d.get("class"):
        table.add_row("Class", f"{d['class']} ({d.get('endian', '?')} endian)")
    if d.get("machine"):
        table.add_row("Machine", d["machine"])
    if d.get("type"):
        table.add_row("Type", d["type"])
    if d.get("entry"):
        table.add_row("Entry", d["entry"])
    if "stripped" in d:
        table.add_row("Stripped", "yes" if d["stripped"] else "no")
    if "strings" in d:
        table.add_row("Strings found", str(d["strings"]))
    console.print(table)

    if segments and d.get("segments"):
        t = Table(title="[bold]Segments[/bold]", border_style="cyan")
        for col in ("Type", "Flags", "Offset", "VAddr", "FileSz", "MemSz"):
            t.add_column(col)
        for s in d["segments"]:
            t.add_row(s["type_name"], s["flags_str"], hex(s["offset"]),
                      hex(s["vaddr"]), str(s["filesz"]), str(s["memsz"]))
        console.print(t)

    if sections and d.get("sections"):
        t = Table(title="[bold]Sections[/bold]", border_style="cyan")
        for col in ("Idx", "Name", "Type", "Addr", "Size"):
            t.add_column(col)
        for s in d["sections"][:60]:
            t.add_row(str(s["index"]), s["name"], s["type_name"], hex(s["addr"]), str(s["size"]))
        console.print(t)

    if imports and d.get("imports"):
        syms = d["imports"]
        console.print(f"[cyan]Dynamic symbols/imports ({d.get('dyn_imports_count', len(syms))}):[/cyan]")
        console.print("  " + "  ".join(syms))
        if d.get("interesting_imports"):
            console.print(f"[yellow]Interesting:[/yellow] {', '.join(d['interesting_imports'])}")

    if d.get("note"):
        rprint(f"[yellow]{d['note']}[/yellow]")


@app.command("disasm")
def disasm_cmd(
    path: str = typer.Argument(..., help="Path to binary"),
    offset: int = typer.Option(0, help="Start offset"),
    length: int = typer.Option(100, help="Number of instructions"),
):
    """Disassemble binary code (wraps radare2 or objdump)."""
    plugin_cls = PluginRegistry.get("reverse", "disasm")
    if not plugin_cls:
        rprint("[red]disasm plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(path, offset=offset, length=length))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    table = Table(title=f"Disassembly ({d['method']})", border_style="cyan")
    table.add_column("Address", style="yellow", width=16)
    table.add_column("Mnemonic", style="cyan", width=10)
    table.add_column("Operands")
    for inst in d["instructions"][:length]:
        table.add_row(inst.get("address", ""), inst.get("mnemonic", ""), inst.get("operands", inst.get("opcode", "")))
    console.print(table)


@app.command("shellcode")
def shellcode_cmd(
    path: str = typer.Argument(..., help="Path to binary"),
):
    """Extract shellcode patterns from a binary."""
    plugin_cls = PluginRegistry.get("reverse", "shellcode_extract")
    if not plugin_cls:
        rprint("[red]shellcode_extract plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(path))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    console.print(f"[cyan]File:[/cyan] {path} ({d['file_size']:,} bytes)")
    console.print(f"[cyan]Shellcode patterns:[/cyan] {d['pattern_count']}")
    for p in d["shellcode_patterns"]:
        console.print(f"  [yellow]{p['pattern']}[/yellow] at {p['hex_offset']} ({p['length']} bytes)")
    console.print(f"\n[cyan]Interesting opcodes:[/cyan] {d['opcode_count']}")
    for op in d["interesting_opcodes"][:20]:
        console.print(f"  {op['offset']:>10s}  {op['opcode']:>10s}  {op['mnemonic']}")