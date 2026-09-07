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
import ctf.modules.recon.dns_lookup
import ctf.modules.recon.whois_lookup
import ctf.modules.recon.ssl_check
import ctf.modules.crypto.encoder
import ctf.modules.crypto.hash_id
import ctf.modules.crypto.caesar
import ctf.modules.crypto.xor_tool
import ctf.modules.crypto.rsa_analyze
import ctf.modules.crypto.freq_analysis
import ctf.modules.forensic.file_inspect
import ctf.modules.forensic.binwalk_scan
import ctf.modules.forensic.strings_extract
import ctf.modules.forensic.hash_calc
import ctf.modules.forensic.hexdump_view
import ctf.modules.forensic.pdf_analyze
import ctf.modules.forensic.ole_analyze
import ctf.modules.forensic.volatility_analyze
import ctf.modules.forensic.exiftool_gui
import ctf.modules.web.http
import ctf.modules.web.jwt_decode
import ctf.modules.web.cookies
import ctf.modules.web.dir_enum
import ctf.modules.reverse.binary_info
import ctf.modules.reverse.disasm
import ctf.modules.reverse.shellcode_extract
import ctf.modules.pwn.checksec
import ctf.modules.pwn.cyclic
import ctf.modules.pwn.rop_search
import ctf.modules.stego.steg_detect

from ctf.cli.commands import recon, crypto, forensic, workspace, web_cmd, tools, reverse, pwn, stego, exiftool

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
app.add_typer(reverse.app,   name="reverse",   help="Reverse engineering tools (binary info, …)")
app.add_typer(pwn.app,       name="pwn",       help="Pwn tools (checksec, cyclic patterns, ROP search, …)")
app.add_typer(web_cmd.app,   name="web",       help="Web: dashboard server + HTTP recon tools")
app.add_typer(stego.app,     name="stego",     help="Steganography detection and analysis")
app.add_typer(exiftool.app,  name="exiftool",  help="ExifTool GUI: metadata viewer/editor")


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
