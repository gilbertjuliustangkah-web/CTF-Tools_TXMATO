"""
Reverse - Binary Info Plugin
Parses ELF (and basic PE/Mach-O) headers, segments, sections, and imports.
"""
from pathlib import Path

from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core import workspace as ws_util
from ctf.modules.forensic.file_inspect import MAGIC_SIGNATURES
from ctf.modules.reverse.elfparse import parse_elf

MACHO_MAGIC = {
    0xFEEDFACE: "Mach-O 32-bit",
    0xFEEDFACF: "Mach-O 64-bit",
    0xCAFEBABE: "Mach-O universal (fat)",
    0xCEFAEDFE: "Mach-O 32-bit (reverse)",
    0xCFFAEDFE: "Mach-O 64-bit (reverse)",
}

PE_MACHINES = {
    0x14C: "x86",
    0x8664: "x86-64",
    0x1C0: "ARM",
    0xAA64: "AArch64",
}

PE_SUBSYSTEMS = {
    1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 9: "WINDOWS_CE_GUI",
}


def _detect_magic(raw: bytes) -> str:
    for sig, name in MAGIC_SIGNATURES:
        if raw[: len(sig)] == sig or raw[4 : 4 + len(sig)] == sig:
            return name
    magic32 = int.from_bytes(raw[:4], "big")
    if magic32 in MACHO_MAGIC:
        return MACHO_MAGIC[magic32]
    return "Unknown / Data"


def _parse_pe(raw: bytes, path: str) -> dict:
    """Minimal PE parsing: COFF header, sections, subsystem, imports hint."""
    import struct

    if len(raw) < 0x40:
        return {"magic": "PE/Windows Executable", "note": "file too small"}
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    if e_lfanew + 24 > len(raw) or raw[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {"magic": "PE/Windows Executable", "note": "invalid PE header"}
    coff = e_lfanew + 4
    machine = struct.unpack_from("<H", raw, coff)[0]
    nsec = struct.unpack_from("<H", raw, coff + 2)[0]
    opt_size = struct.unpack_from("<H", raw, coff + 16)[0]
    opt = coff + 20
    subsystem = struct.unpack_from("<H", raw, opt + 68)[0] if opt_size >= 70 else 0
    entry_rva = struct.unpack_from("<I", raw, opt + 16)[0] if opt_size >= 24 else 0

    sections = []
    soff = opt + opt_size
    for i in range(min(nsec, 32)):
        s = soff + i * 40
        if s + 40 > len(raw):
            break
        name = raw[s:s + 8].rstrip(b"\x00").decode(errors="replace")
        vsize = struct.unpack_from("<I", raw, s + 8)[0]
        vaddr = struct.unpack_from("<I", raw, s + 12)[0]
        sections.append({"name": name, "vaddr": vaddr, "vsize": vsize})

    return {
        "magic": "PE/Windows Executable",
        "machine": PE_MACHINES.get(machine, f"0x{machine:X}"),
        "subsystem": PE_SUBSYSTEMS.get(subsystem, subsystem),
        "entry_rva": hex(entry_rva),
        "sections": sections,
    }


@register_plugin
class BinaryInfo(PluginBase):
    name = "binary_info"
    description = "Parse binary headers, segments, sections, imports"
    category = "reverse"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        sandbox = kwargs.get("sandbox")
        if sandbox:
            path = ws_util.resolve_sandboxed(target, sandbox)
            if path is None:
                return PluginResult(
                    module="reverse", plugin="binary_info", target=target,
                    success=False,
                    error=f"Access denied: '{target}' is outside the active workspace directory.",
                )
        else:
            path = Path(target)

        if not path.exists():
            return PluginResult(
                module="reverse", plugin="binary_info", target=target,
                success=False, error=f"File not found: {target}"
            )

        raw = path.read_bytes()
        data = {
            "path": str(path.resolve()),
            "size": len(raw),
            "magic": _detect_magic(raw),
        }

        if raw[:4] == b"\x7fELF":
            info = parse_elf(path)
            if info:
                data["format"] = "ELF"
                data["class"] = "ELF64" if info.arch_64 else "ELF32"
                data["endian"] = "little" if info.endian == "<" else "big"
                data["type"] = info.etype_name
                data["machine"] = info.machine_name
                data["entry"] = hex(info.entry)
                data["stripped"] = not info.has_symtab
                data["strings"] = info.strings
                data["segments"] = info.segments
                data["sections"] = info.sections
                imports = [nm for nm, kind, _ in info.dynsyms if kind == "import"]
                data["imports"] = imports[:60]
                data["dyn_imports_count"] = len(imports)
                interesting = [nm for nm in imports
                               if any(k in nm for k in ("system", "exec", "flag", "win", "read", "open", "mprotect",
                                                        "gets", "printf", "strcpy", "vuln", "canary"))]
                data["interesting_imports"] = interesting
        elif raw[:2] == b"MZ":
            data["format"] = "PE"
            data.update(_parse_pe(raw, str(path)))
        else:
            # Not an executable — still useful: strings + entropy.
            data["format"] = _detect_magic(raw)
            data["note"] = "Not ELF/PE/Mach-O — treated as data."
            strings = []
            import re
            for m in re.finditer(rb"[ -~]{6,}", raw):
                s = m.group().decode(errors="replace")
                if s not in strings:
                    strings.append(s)
                if len(strings) >= 100:
                    break
            data["strings"] = strings
            data["entropy"] = round(self._entropy(raw), 4)

        return PluginResult(
            module="reverse", plugin="binary_info", target=target,
            success=True, data=data
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _entropy(self, data: bytes) -> float:
        import math
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        return -sum((f / n) * math.log2(f / n) for f in freq if f)