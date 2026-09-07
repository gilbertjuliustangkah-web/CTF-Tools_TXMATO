"""
Forensic - Binwalk Scan Plugin
Firmware / file analysis and carving using binwalk.
"""
import re
from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core.process import run, is_available


@register_plugin
class BinwalkScan(PluginBase):
    name = "binwalk_scan"
    description = "Scan files with binwalk: magic signatures, entropy, carving"
    category = "forensic"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        if not is_available("binwalk"):
            return PluginResult(
                module="forensic", plugin="binwalk_scan", target=target,
                success=False,
                error="binwalk not found. Install: pip install binwalk or apt install binwalk"
            )

        mode = kwargs.get("mode", "signature")
        args = ["binwalk"]

        if mode == "extract":
            args.append("-e")
        elif mode == "entropy":
            args.append("-E")

        args.append(target)
        result = await run(*args, timeout=120)

        if not result.ok and not result.stdout:
            return PluginResult(
                module="forensic", plugin="binwalk_scan", target=target,
                success=False, error=result.stderr or "binwalk failed"
            )

        data = self._parse_output(result.stdout, mode)
        return PluginResult(
            module="forensic", plugin="binwalk_scan", target=target,
            success=True, data=data
        )

    def parse(self, raw_output: str) -> dict:
        return self._parse_output(raw_output, "signature")

    def _parse_output(self, output: str, mode: str) -> dict:
        signatures = []
        for line in output.splitlines():
            line = line.strip()
            m = re.match(r"(\d+)\s+(0x[0-9a-fA-F]+)\s+(.+)", line)
            if m:
                signatures.append({
                    "offset": int(m.group(1)),
                    "hex_offset": m.group(2),
                    "description": m.group(3),
                })
        return {
            "mode": mode,
            "signatures": signatures,
            "count": len(signatures),
            "raw": output,
        }
