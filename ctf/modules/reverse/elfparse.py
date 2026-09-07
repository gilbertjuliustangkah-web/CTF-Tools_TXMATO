"""
Reverse - ELF parsing utilities.

Pure-python, dependency-free ELF32/ELF64 parser used by the reverse and pwn
plugins (binary_info, checksec). Minimal but covers the fields CTF players
care about: header, segments, sections, .dynamic (RELRO/RPATH), .dynsym names.
"""
import struct
from dataclasses import dataclass, field

MACHINES = {
    0x03: "x86",
    0x3E: "x86-64",
    0x08: "MIPS",
    0x28: "ARM",
    0xB7: "AArch64",
    0xF3: "RISC-V",
    0x14: "PowerPC",
    0x15: "PowerPC64",
    0x16: "S390x",
    0x02: "SPARC",
    0x2A: "SuperH",
}

ETYPES = {0: "NONE", 1: "REL (relocatable)", 2: "EXEC", 3: "DYN (PIE/shared)", 4: "CORE"}

PT_TYPES = {
    0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
    6: "PHDR", 7: "TLS", 0x6474e551: "GNU_STACK", 0x6474e552: "GNU_RELRO",
    0x6474e553: "GNU_PROPERTY", 0x6474e554: "GNU_EH_FRAME",
}

SH_TYPES = {
    0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
    5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
    11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY", 17: "GROUP",
}

DT_BIND_NOW = 24
DT_RPATH = 15
DT_RUNPATH = 29


@dataclass
class ElfInfo:
    path: str
    arch_64: bool
    endian: str                 # "<" little | ">" big
    etype: int
    etype_name: str
    machine: int
    machine_name: str
    entry: int
    segments: list[dict] = field(default_factory=list)
    sections: list[dict] = field(default_factory=list)
    dynsyms: list[tuple] = field(default_factory=list)   # (name, kind, value)
    dynamic_flags: list[str] = field(default_factory=list)
    has_symtab: bool = False    # False → stripped
    strings: int = 0            # number of readable strings found


def _u(ei, fmt, data, off):
    return struct.unpack_from(ei.format + fmt, data, off)[0]


def parse_elf(path) -> ElfInfo | None:
    """Parse an ELF file. Returns ElfInfo or None if not an ELF."""
    try:
        data = open(path, "rb").read()
    except OSError:
        return None
    if len(data) < 16 or data[:4] != b"\x7fELF":
        return None

    arch_64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    ei = struct.Struct(endian)
    etype = _u(ei, "H", data, 16)
    machine = _u(ei, "H", data, 18)
    if arch_64:
        entry = _u(ei, "Q", data, 24)
        phoff, shoff = _u(ei, "Q", data, 32), _u(ei, "Q", data, 40)
        phentsize, phnum = _u(ei, "H", data, 54), _u(ei, "H", data, 56)
        shentsize, shnum, shstrndx = _u(ei, "H", data, 58), _u(ei, "H", data, 60), _u(ei, "H", data, 62)
    else:
        entry = _u(ei, "I", data, 24)
        phoff, shoff = _u(ei, "I", data, 28), _u(ei, "I", data, 32)
        phentsize, phnum = _u(ei, "H", data, 42), _u(ei, "H", data, 44)
        shentsize, shnum, shstrndx = _u(ei, "H", data, 46), _u(ei, "H", data, 48), _u(ei, "H", data, 50)

    info = ElfInfo(
        path=str(path),
        arch_64=arch_64,
        endian=endian,
        etype=etype,
        etype_name=ETYPES.get(etype, f"UNKNOWN({etype})"),
        machine=machine,
        machine_name=MACHINES.get(machine, f"0x{machine:x}"),
        entry=entry,
    )

    # Program headers (segments)
    if phoff and phentsize >= 32:
        for i in range(min(phnum, 64)):
            off = phoff + i * phentsize
            if arch_64:
                type_ = _u(ei, "I", data, off)
                flags = _u(ei, "I", data, off + 4)
                seg = {
                    "type": type_, "type_name": PT_TYPES.get(type_, f"0x{type_:x}"),
                    "flags": flags, "flags_str": _pf(flags),
                    "offset": _u(ei, "Q", data, off + 8),
                    "vaddr": _u(ei, "Q", data, off + 16),
                    "filesz": _u(ei, "Q", data, off + 32),
                    "memsz": _u(ei, "Q", data, off + 40),
                }
            else:
                type_ = _u(ei, "I", data, off)
                flags = _u(ei, "I", data, off + 24)
                seg = {
                    "type": type_, "type_name": PT_TYPES.get(type_, f"0x{type_:x}"),
                    "flags": flags, "flags_str": _pf(flags),
                    "offset": _u(ei, "I", data, off + 4),
                    "vaddr": _u(ei, "I", data, off + 8),
                    "filesz": _u(ei, "I", data, off + 16),
                    "memsz": _u(ei, "I", data, off + 20),
                }
            info.segments.append(seg)

    # Section headers + section name table
    shstr = b""
    section_names = []
    if shoff and shentsize >= 40:
        # read shstrtab (index shstrndx) first
        if shstrndx < shnum:
            soff_base = shoff + shstrndx * shentsize
            name_off = _u(ei, "I", data, soff_base) if arch_64 else _u(ei, "I", data, soff_base)
            sh_off = _u(ei, "Q", data, soff_base + 24) if arch_64 else _u(ei, "I", data, soff_base + 16)
            sh_size = _u(ei, "Q", data, soff_base + 32) if arch_64 else _u(ei, "I", data, soff_base + 20)
            if sh_off and sh_size <= len(data):
                shstr = data[sh_off: sh_off + sh_size]

        for i in range(min(shnum, 128)):
            so = shoff + i * shentsize
            if arch_64:
                name_idx = _u(ei, "I", data, so)
                stype = _u(ei, "I", data, so + 4)
                s_addr = _u(ei, "Q", data, so + 16)
                s_off = _u(ei, "Q", data, so + 24)
                s_size = _u(ei, "Q", data, so + 32)
            else:
                name_idx = _u(ei, "I", data, so)
                stype = _u(ei, "I", data, so + 4)
                s_addr = _u(ei, "I", data, so + 12)
                s_off = _u(ei, "I", data, so + 16)
                s_size = _u(ei, "I", data, so + 20)
            name = _cstr(shstr, name_idx)
            if name:
                section_names.append((i, name, stype, s_addr, s_off, s_size))
                info.sections.append({
                    "index": i,
                    "name": name,
                    "type": stype,
                    "type_name": SH_TYPES.get(stype, f"0x{stype:x}"),
                    "addr": s_addr,
                    "size": s_size,
                })
                if name == ".symtab":
                    info.has_symtab = True

    # Dynamic symbols (imports) — read .dynsym + .dynstr + .dynamic
    dynsym = next((s for s in info.sections if s["name"] == ".dynsym"), None)
    dynstr = next((s for s in info.sections if s["name"] == ".dynstr"), None)
    if dynsym and dynstr:
        ent = 24 if arch_64 else 16
        ds_off = _sec_file_off(info, dynsym)
        ds_data = data[ds_off: ds_off + dynsym["size"]]
        str_off = _sec_file_off(info, dynstr)
        str_data = data[str_off: str_off + dynstr["size"]] or b""
        nsym = dynsym["size"] // ent
        if ds_data:
            max_sz = len(ds_data)
            for i in range(nsym):
                if (i * ent + (24 if arch_64 else 16)) > max_sz:
                    break
                if arch_64:
                    name_idx = _u(ei, "I", ds_data, i * ent)
                    sym_type = _u(ei, "B", ds_data, i * ent + 4) & 0x0F
                    shndx = _u(ei, "H", ds_data, i * ent + 6)
                    value = _u(ei, "Q", ds_data, i * ent + 8)
                else:
                    name_idx = _u(ei, "I", ds_data, i * ent)
                    sym_type = _u(ei, "B", ds_data, i * ent + 12) & 0x0F
                    shndx = _u(ei, "H", ds_data, i * ent + 14)
                    value = _u(ei, "I", ds_data, i * ent + 4)
                nm = _cstr(str_data, name_idx)
                if not nm:
                    continue
                if shndx == 0:
                    kind = "import"
                elif sym_type == 2:
                    kind = "func"
                else:
                    kind = "data"
                info.dynsyms.append((nm, kind, value))

    # .dynamic → DT_BIND_NOW / DT_RPATH / DT_RUNPATH (used by checksec)
    dyn = next((s for s in info.sections if s["name"] == ".dynamic"), None)
    info.dynamic_flags = []
    if dyn:
        off = _sec_file_off(info, dyn)
        blob = data[off: off + dyn["size"]]
        esz = 16 if arch_64 else 8
        i = 0
        while i + esz <= len(blob):
            if arch_64:
                tag, val = _u(ei, "q", blob, i), _u(ei, "Q", blob, i + 8)
            else:
                tag, val = _u(ei, "i", blob, i), _u(ei, "I", blob, i + 4)
            if tag == 0:
                break
            if tag == DT_BIND_NOW:
                info.dynamic_flags.append("BIND_NOW")
            elif tag == DT_RPATH:
                info.dynamic_flags.append("RPATH")
            elif tag == DT_RUNPATH:
                info.dynamic_flags.append("RUNPATH")
            i += esz

    # Heuristic strings count (rough measure of "how juicy" binary is)
    import re
    info.strings = len(re.findall(rb"[ -~]{6,}", data))

    return info


def _pf(flags: int) -> str:
    s = ""
    s += "R" if flags & 4 else "-"
    s += "W" if flags & 2 else "-"
    s += "X" if flags & 1 else "-"
    return s


def _cstr(buf: bytes, off: int) -> str:
    if off <= 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off)
    if end == -1:
        return ""
    try:
        return buf[off:end].decode()
    except UnicodeDecodeError:
        return ""


def _sec_file_off(info: ElfInfo, section: dict) -> int:
    """Map a section's vaddr to a file offset via LOAD segments."""
    for seg in info.segments:
        if seg["type"] != 1:  # LOAD
            continue
        start, end = seg["vaddr"], seg["vaddr"] + seg["filesz"]
        if start <= section["addr"] < end:
            return section["addr"] - seg["vaddr"] + seg["offset"]
    return section["addr"]  # optimistic fallback (identity mapping)