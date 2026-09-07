"""
Reverse - Shellcode Extractor Plugin
Extract shellcode patterns and known opcodes from binaries.
"""
import re
from ctf.core.plugin import PluginBase, PluginResult, register_plugin


@register_plugin
class ShellcodeExtract(PluginBase):
    name = "shellcode_extract"
    description = "Extract shellcode patterns: opcodes, INT 0x80/syscall, NOP sleds"
    category = "reverse"

    SHELLCODE_PATTERNS = {
        "x86_linux_syscall": rb"\x31\xc0\x31\xdb\x31\xc9\x31\xd2",
        "x86_linux_int80": rb"\xcd\x80",
        "x86_nop_sled": rb"\x90{16,}",
        "x86_push_pop": rb"\x68[\x00-\xff]{4}\xc3",
        "x64_syscall": rb"\x0f\x05",
        "x64_linux_shell": rb"\x48\x31\xf6\x56\x48\xbf",
        "mips_nop": rb"\x00\x00\x00\x00{8,}",
        "arm_nop": rb"\x00\x00\xa0\xe1{4,}",
    }

    OPCODE_MAP = {
        b"\x90": "NOP",
        b"\xcc": "INT3 (breakpoint)",
        b"\xcd\x80": "INT 0x80 (Linux syscall)",
        b"\x0f\x05": "SYSCALL (x64)",
        b"\xc3": "RET",
        b"\x55": "PUSH EBP",
        b"\x89\xe5": "MOV EBP, ESP",
        b"\xeb": "JMP short",
        b"\xe8": "CALL rel32",
        b"\xff\x15": "CALL [ptr]",
        b"\x6a": "PUSH imm8",
        b"\x68": "PUSH imm32",
    }

    async def execute(self, target: str, **kwargs) -> PluginResult:
        try:
            with open(target, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return PluginResult(
                module="reverse", plugin="shellcode_extract", target=target,
                success=False, error=f"File not found: {target}"
            )

        findings = []
        for name, pattern in self.SHELLCODE_PATTERNS.items():
            for m in re.finditer(pattern, data):
                findings.append({
                    "pattern": name,
                    "offset": m.start(),
                    "hex_offset": f"0x{m.start():x}",
                    "length": len(m.group()),
                    "context": data[max(0, m.start()-4):m.end()+4].hex(" "),
                })

        opcodes = self._find_opcodes(data)

        return PluginResult(
            module="reverse", plugin="shellcode_extract", target=target,
            success=True,
            data={
                "file_size": len(data),
                "shellcode_patterns": findings,
                "pattern_count": len(findings),
                "interesting_opcodes": opcodes[:50],
                "opcode_count": len(opcodes),
            }
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _find_opcodes(self, data: bytes) -> list[dict]:
        opcodes = []
        for opcode_bytes, mnemonic in self.OPCODE_MAP.items():
            offset = 0
            while True:
                idx = data.find(opcode_bytes, offset)
                if idx == -1:
                    break
                opcodes.append({
                    "offset": f"0x{idx:x}",
                    "opcode": opcode_bytes.hex(),
                    "mnemonic": mnemonic,
                })
                offset = idx + 1
                if len(opcodes) >= 200:
                    break
            if len(opcodes) >= 200:
                break
        return opcodes
