
## CTF-Tools_TXMATO

CTF Tools Hybrid, CLI and Local Web

## Quick start (npm)

```bash
npm run setup      # create .venv + install Python deps (run once)
npm start          # launch the web dashboard → http://localhost:8080
npm run cli -- --help    # run the CLI (any ctf command)
npm run dev        # dashboard with auto-reload (dev mode)
npm test           # run the pytest suite
npm run doctor     # tool catalog status
```

`npm install` runs `setup` automatically via `postinstall`.

- CLI equivalent: after `npm run setup`, use `npm run cli -- <args>` or `` .venv\Scripts\activate && ctf ... ``
- Optional external tools (exiftool, binwalk, volatility3, dig, whois, gobuster, r2, objdump, ropper, ROPgadget) are auto-detected; everything degrades gracefully when missing.
- Classic launchers still work: `install.bat` then `start.bat`.

## Tool categories

- `recon` — port scan, DNS, WHOIS, SSL/TLS cert review
- `crypto` — encode/decode, hash-id, Caesar, single-byte XOR, RSA audit, frequency analysis
- `forensic` — file inspect, strings, hash calc, hex dump, PDF/OLE/volatility/binwalk, ExifTool GUI
- `web` — headers, robots.txt, JWTs, cookies, dir enumeration, WSL web terminal, dashboard server
- `reverse` — ELF/PE info, disassembly, shellcode extraction
- `pwn` — checksec, cyclic pattern, ROP gadget search
- `stego` — steganography detection/heuristics
- `workspace` / `tools` — per-challenge state + external tool catalog
- `python` — write & run Python 3 in the browser (runs from active workspace, saved to DB)
