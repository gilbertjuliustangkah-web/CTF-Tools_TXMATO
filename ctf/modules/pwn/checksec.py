"""
Pwn - Checksec Plugin
Detects binary hardening: PIE, NX, RELRO, stack canary, FORTIFY, RPATH.
"""
from pathlib import Path

from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core import workspace as ws_util
from ctf.modules.reverse.elfparse import parse_elf
from ctf.modules.forensic.file_inspect import MAGIC_SIGNATURES


def _detect_magic(raw: bytes) -> str:
    for sig, name in MAGIC_SIGNATURES:
        if raw[: len(sig)] == sig or raw[4 : 4 + len(sig)] == sig:
            return name
    return "Unknown / Data"


def _flags(flags: int) -> str:
    s = ""
    s += "R" if flags & 4 else "-"
    s += "W" if flags & 2 else "-"
    s += "X" if flags & 1 else "-"
    return s


@register_plugin
class Checksec(PluginBase):
    name = "checksec"
    description = "Check binary hardening: PIE, NX, RELRO, canary, fortify"
    category = "pwn"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        sandbox = kwargs.get("sandbox")
        if sandbox:
            path = ws_util.resolve_sandboxed(target, sandbox)
            if path is None:
                return PluginResult(
                    module="pwn", plugin="checksec", target=target,
                    success=False,
                    error=f"Access denied: '{target}' is outside the active workspace directory.",
                )
        else:
            path = Path(target)

        if not path.exists():
            return PluginResult(
                module="pwn", plugin="checksec", target=target,
                success=False, error=f"File not found: {target}"
            )

        raw = path.read_bytes()
        if raw[:4] != b"\x7fELF":
            return PluginResult(
                module="pwn", plugin="checksec", target=target,
                success=False,
                error=f"Not an ELF binary (type: {_detect_magic(raw)}). Checksec works on ELF files."
            )

        info = parse_elf(path)
        if info is None:
            return PluginResult(
                module="pwn", plugin="checksec", target=target,
                success=False, error=f"Could not parse ELF: {target}"
            )

        seg_types = {s["type"] for s in info.segments}
        interp = next((s for s in info.segments if s["type_name"] == "INTERP"), None)
        gnu_stack = next((s for s in info.segments if s["type_name"] == "GNU_STACK"), None)
        gnu_relro = next((s for s in info.segments if s["type_name"] == "GNU_RELRO"), None)

        # PIE: DYN + has PT_INTERP → PIE executable; DYN without interp → shared lib
        if info.etype == 3:
            pie = "PIE enabled (ET_DYN)"
            if not interp:
                pie = "DYN — shared library or PIE (no PT_INTERP)"
        else:
            pie = "No (ET_EXEC / fixed base)" if info.etype == 2 else info.etype_name

        # NX: NX is ENABLED when the stack segment is NOT executable
        if gnu_stack is None:
            nx = "Enabled (no PT_GNU_STACK, assumed non-exec)"
        elif gnu_stack["flags"] & 1:
            nx = "Disabled — stack is executable"
        else:
            nx = "Enabled"

        # RELRO
        if gnu_relro:
            relro = "FULL" if "BIND_NOW" in info.dynamic_flags else "PARTIAL"
        else:
            relro = "No"

        # Canary / fortify: heuristic — look for the sentinel/fail symbols
        canary = "Yes" if b"__stack_chk_fail" in raw else "No"
        fortify = "Yes" if b"__fortify_fail" in raw or b"__printf_chk" in raw else "No"

        rpath = "Yes" if any(f in info.dynamic_flags for f in ("RPATH", "RUNPATH")) else "No"

        data = {
            "path": str(path.resolve()),
            "class": "ELF64" if info.arch_64 else "ELF32",
            "endian": "little" if info.endian == "<" else "big",
            "type": info.etype_name,
            "machine": info.machine_name,
            "entry": hex(info.entry),
            "pie": pie,
            "nx": nx,
            "relro": relro,
            "canary": canary,
            "fortify": fortify,
            "rpath": rpath,
            "stripped": not info.has_symtab,
        }

        # Advisory notes for exploitation planning
        advice = []
        if "PIE enabled" in pie:
            advice.append("ASLR + PIE: you need a leak to compute base address (or one-gadget w/o relocation).")
        elif pie.startswith("No"):
            advice.append("Non-PIE: fixed base — addresses are stable across runs.")
        if "Disabled" in nx:
            advice.append("NX disabled: shellcode on the stack is possible.")
        if canary == "No":
            advice.append("No stack canary: classic buffer overflow / ROP on the stack is viable.")
        if relro == "No":
            advice.append("No RELRO: GOT is writable — GOT overwrite is viable.")
        elif relro == "PARTIAL":
            advice.append("Partial RELRO: .got.plt is still writable — GOT overwrite possible.")
        if fortify == "No":
            advice.append("No FORTIFY: unchecked printf/strcpy-like functions may be exploitable directly.")
        data["advice"] = advice

        return PluginResult(
            module="pwn", plugin="checksec", target=target,
            success=True, data=data
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}