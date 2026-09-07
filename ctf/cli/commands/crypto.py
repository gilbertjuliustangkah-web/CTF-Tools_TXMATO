"""
CLI - Crypto Commands
"""
import asyncio
import typer
from rich.console import Console
from rich import print as rprint
from rich.panel import Panel
from rich.table import Table

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


@app.command("hash-id")
def hash_identify(
    hash_str: str = typer.Argument(..., help="Hash string to identify"),
):
    """Identify hash type from length and pattern."""
    plugin_cls = PluginRegistry.get("crypto", "hash_id")
    if not plugin_cls:
        rprint("[red]hash_id plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(hash_str))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    console.print(f"[cyan]Hash:[/cyan] {d['hash'][:40]}...")
    console.print(f"[cyan]Length:[/cyan] {d['length']}")
    rprint(f"[green]Likely types:[/green] {', '.join(d['candidates'])}")


@app.command("caesar")
def caesar_brute(
    text: str = typer.Argument(..., help="Ciphertext to brute-force"),
    shift: int = typer.Option(None, help="Specific shift (omit for all 26)"),
):
    """Brute-force Caesar/ROT cipher."""
    plugin_cls = PluginRegistry.get("crypto", "caesar_brute")
    if not plugin_cls:
        rprint("[red]caesar_brute plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(text, shift=shift))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    table = Table(title="Caesar Brute-Force", border_style="cyan")
    table.add_column("Shift", style="yellow", width=6)
    table.add_column("Score", width=8)
    table.add_column("Plaintext")
    for r in d["results"][:10]:
        table.add_row(str(r["shift"]), str(r["score"]), r["text"][:60])
    console.print(table)
    rprint(f"[green]Best shift:[/green] {d['best_shift']}")


@app.command("xor")
def xor_cmd(
    data: str = typer.Argument(..., help="Data (hex or text)"),
    mode: str = typer.Option("decrypt", help="Mode: encrypt | decrypt | single_byte"),
    key: str = typer.Option("", help="XOR key (hex or text)"),
):
    """XOR cipher: encrypt, decrypt, or single-byte crack."""
    plugin_cls = PluginRegistry.get("crypto", "xor_tool")
    if not plugin_cls:
        rprint("[red]xor_tool plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(data, mode=mode, key=key))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    if "result_text" in d:
        console.print(Panel(d["result_text"], title="XOR Result", border_style="cyan"))
    if "result_hex" in d:
        console.print(f"[dim]Hex:[/dim] {d['result_hex'][:80]}")
    if "best_text" in d:
        console.print(Panel(d["best_text"], title=f"Best key: {d['best_key_hex']}", border_style="green"))


@app.command("freq")
def freq_analysis(
    text: str = typer.Argument(..., help="Text to analyze"),
):
    """Letter frequency analysis for classical ciphers."""
    plugin_cls = PluginRegistry.get("crypto", "freq_analysis")
    if not plugin_cls:
        rprint("[red]freq_analysis plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(text))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    console.print(f"[cyan]Letters:[/cyan] {d['letter_count']} total, {d['unique_letters']} unique")
    console.print(f"[cyan]Top 5:[/cyan]")
    for ch, pct in d["top_5"]:
        bar = "#" * int(pct / 2)
        console.print(f"  {ch}: {pct:5.1f}%  {bar}")
    rprint(f"[green]Likely Caesar shift:[/green] {d['likely_caesar_shift']}")
    rprint(f"[dim]Chi-squared (lower=better):[/dim] {d['chi_squared']}")


@app.command("rsa")
def rsa_analyze(
    data: str = typer.Argument(..., help="RSA key data (n=, e=, d=, p=, q= values)"),
):
    """Analyze RSA key parameters for vulnerabilities."""
    plugin_cls = PluginRegistry.get("crypto", "rsa_analyze")
    if not plugin_cls:
        rprint("[red]rsa_analyze plugin not found.[/red]")
        raise typer.Exit(1)

    result = asyncio.run(plugin_cls().execute(data))
    if not result.success:
        rprint(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(1)

    d = result.data
    table = Table(title="RSA Key Analysis", border_style="cyan")
    table.add_column("Field", style="dim", width=16)
    table.add_column("Value")
    for k in ["n", "e", "d", "p", "q", "key_bits", "is_public_only"]:
        if d.get(k) is not None:
            val = str(d[k])
            if len(val) > 60:
                val = val[:60] + "..."
            table.add_row(k, val)
    console.print(table)

    for v in d.get("vulnerabilities", []):
        rprint(f"  [red]! {v}[/red]")
