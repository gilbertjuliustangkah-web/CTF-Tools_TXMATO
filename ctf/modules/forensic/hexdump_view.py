"""
Forensic - Hex Dump Viewer Plugin
Pure Python hex dump with configurable options.
"""
from ctf.core.plugin import PluginBase, PluginResult, register_plugin


@register_plugin
class HexdumpView(PluginBase):
    name = "hexdump_view"
    description = "View hex dump of files with offset, ASCII, and highlighting"
    category = "forensic"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        offset = kwargs.get("offset", 0)
        length = kwargs.get("length", 256)
        group_size = kwargs.get("group_size", 1)

        try:
            with open(target, "rb") as f:
                f.seek(offset)
                data = f.read(length)
        except FileNotFoundError:
            return PluginResult(
                module="forensic", plugin="hexdump_view", target=target,
                success=False, error=f"File not found: {target}"
            )
        except PermissionError:
            return PluginResult(
                module="forensic", plugin="hexdump_view", target=target,
                success=False, error=f"Permission denied: {target}"
            )

        lines = self._format_hexdump(data, offset, group_size)
        total_size = 0
        try:
            import os
            total_size = os.path.getsize(target)
        except Exception:
            pass

        return PluginResult(
            module="forensic", plugin="hexdump_view", target=target,
            success=True,
            data={
                "lines": lines,
                "offset": offset,
                "length": len(data),
                "total_size": total_size,
                "group_size": group_size,
            }
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _format_hexdump(self, data: bytes, base_offset: int = 0, group_size: int = 1) -> list[str]:
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            offset_str = f"{base_offset + i:08x}"

            hex_parts = []
            for j in range(0, len(chunk), group_size):
                group = chunk[j:j + group_size]
                hex_parts.append(group.hex())

            hex_str = " ".join(hex_parts)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{offset_str}  {hex_str:<48s}  |{ascii_str}|")
        return lines
