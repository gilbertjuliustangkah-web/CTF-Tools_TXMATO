"""
Reverse - Disassembly Plugin
Disassemble binaries using radare2 or capstone.
"""
import re
from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core.process import run, is_available


@register_plugin
class Disasm(PluginBase):
    name = "disasm"
    description = "Disassemble binary code (wraps radare2 or capstone)"
    category = "reverse"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        arch = kwargs.get("arch", "x86")
        length = kwargs.get("length", 100)
        offset = kwargs.get("offset", 0)

        if is_available("r2"):
            return await self._r2_disasm(target, offset, length)
        elif is_available("objdump"):
            return await self._objdump_disasm(target, offset, length)

        return PluginResult(
            module="reverse", plugin="disasm", target=target,
            success=False,
            error="No disassembler found. Install radare2 (r2) or objdump."
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    async def _r2_disasm(self, target: str, offset: int, length: int) -> PluginResult:
        cmd = f"pd {length} @ {offset}"
        result = await run("r2", "-q", "-c", cmd, target, timeout=30)

        instructions = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or "-->" in line:
                continue
            parts = line.split(None, 2)
            if len(parts) >= 2:
                addr = parts[0]
                mnemonic = parts[1] if len(parts) > 1 else ""
                op_str = parts[2] if len(parts) > 2 else ""
                instructions.append({"address": addr, "mnemonic": mnemonic, "operands": op_str})

        return PluginResult(
            module="reverse", plugin="disasm", target=target,
            success=True,
            data={
                "target": target,
                "offset": offset,
                "length": length,
                "instructions": instructions,
                "count": len(instructions),
                "method": "radare2",
            }
        )

    async def _objdump_disasm(self, target: str, offset: int, length: int) -> PluginResult:
        result = await run("objdump", "-d", "-M", "intel", target, timeout=30)

        instructions = []
        in_disasm = False
        for line in result.stdout.splitlines():
            if "<" in line and ">" in line:
                in_disasm = True
            if not in_disasm:
                continue
            stripped = line.strip()
            m = re.match(r"([0-9a-f]+):\s+([0-9a-f]+)\s+(.+)", stripped)
            if m:
                instructions.append({
                    "address": m.group(1),
                    "opcode": m.group(2),
                    "mnemonic": m.group(3).split()[0] if m.group(3) else "",
                    "operands": " ".join(m.group(3).split()[1:]) if m.group(3) else "",
                })

        return PluginResult(
            module="reverse", plugin="disasm", target=target,
            success=True,
            data={
                "target": target,
                "instructions": instructions[:length],
                "count": len(instructions),
                "method": "objdump",
            }
        )
