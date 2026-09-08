
# CTF-Tools_TXMATO

A hybrid CLI + local web toolkit for CTF (Capture The Flag) challenges. Built with Python 3, FastAPI, and Typer. Every tool provides both a command-line interface and a browser-based dashboard.

## Features

- **30+ built-in tools** across 9 CTF categories — most work without any external dependencies
- **Dual interface** — every tool is accessible via CLI (`ctf <category> <command>`) and the web dashboard
- **Graceful degradation** — optional external tools (nmap, binwalk, radare2, etc.) are auto-detected; everything falls back to pure-Python implementations when unavailable
- **Plugin architecture** — all tools extend a common `PluginBase` and register into a global registry
- **Workspace management** — per-challenge state, files, flags, and notes stored in SQLite
- **Python code runner** — write and execute Python 3 in the browser, sandboxed to the active workspace
- **WSL terminal** — persistent Linux shell from the browser (Windows)
- **90+ external tool catalog** — browse, install, and monitor CTF tools from the dashboard

## Requirements

- **Python** >= 3.10
- **Node.js** >= 18 (for npm wrapper scripts)
- **Windows** with WSL optional (for Linux-only tools like exiftool, binwalk)

## Quick Start

```bash
# npm (recommended)
npm run setup          # create .venv + install Python deps (run once)
npm start              # launch web dashboard → http://localhost:8080
npm run cli -- --help  # run the CLI
npm run dev            # dashboard with auto-reload (dev mode)
npm test               # run the pytest suite
npm run doctor         # tool catalog status
```

`npm install` runs `setup` automatically via `postinstall`.

### Classic launchers

```batch
install.bat            # create venv + install deps
start.bat              # launch dashboard + open browser
```

### Direct CLI

```bash
.venv\Scripts\activate
ctf --help
```

## Tool Categories

| Category | Description | Tools |
|----------|-------------|-------|
| `recon` | Reconnaissance | Port scan, DNS lookup, WHOIS, SSL/TLS cert analysis |
| `crypto` | Cryptography | Encode/decode, hash ID, Caesar brute-force, XOR, RSA audit, frequency analysis |
| `forensic` | Forensics | File inspect, strings, hash calc, hex dump, PDF/OLE analysis, binwalk, volatility3, ExifTool GUI |
| `web` | Web exploitation | HTTP headers, robots.txt, JWT decode, cookies, directory enumeration |
| `reverse` | Reverse engineering | ELF/PE info, disassembly, shellcode extraction |
| `pwn` | Binary exploitation | checksec, cyclic pattern, ROP gadget search |
| `stego` | Steganography | Steganography detection and heuristics (LSB analysis, appended data, embedded strings) |
| `pentes` | Penetration testing | Subdomain enum, service probe, directory brute-force, auth brute, SQLi detection, XSS detection |
| `workspace` | State management | Per-challenge workspaces, flags, notes, files |
| `tools` | External tools | Tool catalog with 90+ tools, install/uninstall/status |
| `python` | Python runner | Write and execute Python 3 in the browser |

## CLI Usage

The CLI is organized into command groups matching the categories above:

```bash
ctf recon scan 192.168.1.1          # port scan
ctf crypto caesar "Khoor Zruog"     # Caesar brute-force
ctf forensic strings file.bin       # extract strings
ctf pwn checksec ./binary           # check binary hardening
ctf web headers https://example.com # HTTP header analysis
ctf workspace new my-challenge      # create a workspace
ctf tools status                    # check installed tools
```

### External Tools

Optional tools are auto-detected and used when available. Key ones include:

- **Network:** nmap, dig, whois, gobuster, ffuf, sublist3r
- **Binary:** radare2, objdump, ropper, ROPgadget
- **Forensics:** binwalk, exiftool, volatility3
- **Crypto:** RsaCtfTool (vendored in `workspace/tools/rsactftool/`)

Everything degrades gracefully when external tools are missing.

## Web Dashboard

The FastAPI dashboard runs at `http://localhost:8080` and provides:

- **16 route modules** covering all tool categories
- **Python code runner** — execute Python 3 in-browser, sandboxed to the active workspace
- **WSL terminal** — persistent Linux shell
- **Tool catalog** — visual tool management with install/uninstall/status
- **Notes** — per-workspace notes with tagging
- **Security** — HMAC-signed session cookies, CSRF protection, token auth when exposed beyond localhost

## Architecture

```
ctf/
├── core/                 # Infrastructure
│   ├── database.py       # Async SQLite (workspaces, scans, flags, files)
│   ├── workspace.py      # Workspace state manager
│   ├── plugin.py         # Plugin base class + registry
│   ├── process.py        # Async subprocess runner
│   ├── python_runner.py  # Isolated Python executor
│   ├── terminal.py       # WSL persistent terminal
│   └── toolbox.py        # External tool catalog (90+ tools)
├── api/                  # FastAPI web app
│   ├── main.py           # App setup, route mounting
│   ├── security.py       # Auth + CSRF middleware
│   └── routes/           # 16 route modules
├── cli/                  # Typer CLI
│   ├── main.py           # Entry point
│   └── commands/         # 10 command groups
├── modules/              # Plugin modules (by category)
│   ├── recon/
│   ├── crypto/
│   ├── forensic/
│   ├── web/
│   ├── reverse/
│   ├── pwn/
│   ├── stego/
│   └── pentes/
frontend/templates/       # Jinja2 HTML templates
tests/                    # pytest test suite
```

### Design Principles

- **Plugin architecture** — every tool extends `PluginBase` with `execute()` and `parse()`, registered via `@register_plugin`
- **Graceful degradation** — all modules check for external tools and fall back to pure-Python
- **Sandboxed file access** — web-facing operations scoped to the active workspace
- **Input validation** — all user targets validated against regex to prevent injection

## Testing

```bash
npm test
# or
pytest
```

The test suite covers plugin registry, pure-Python tool correctness (Caesar, base64, hash ID, XOR, hexdump, strings, RSA, cyclic patterns, JWT, cookies, stego, SQLi, XSS), database operations, and the Python runner.

## License

MIT
