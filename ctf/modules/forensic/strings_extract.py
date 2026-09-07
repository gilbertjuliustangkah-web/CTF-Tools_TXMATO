"""
Forensic - Enhanced Strings Extraction Plugin
Pure Python strings extraction with encoding support.
"""
import re
from ctf.core.plugin import PluginBase, PluginResult, register_plugin


@register_plugin
class StringsExtract(PluginBase):
    name = "strings_extract"
    description = "Extract printable strings (ASCII, UTF-16, wide) from binary files"
    category = "forensic"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        min_len = kwargs.get("min_length", 4)
        encodings = kwargs.get("encodings", "ascii,utf16")

        try:
            with open(target, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return PluginResult(
                module="forensic", plugin="strings_extract", target=target,
                success=False, error=f"File not found: {target}"
            )
        except PermissionError:
            return PluginResult(
                module="forensic", plugin="strings_extract", target=target,
                success=False, error=f"Permission denied: {target}"
            )

        all_strings = {}
        enc_list = [e.strip().lower() for e in encodings.split(",")]

        if "ascii" in enc_list:
            ascii_strings = self._extract_ascii(data, min_len)
            if ascii_strings:
                all_strings["ascii"] = ascii_strings

        if "utf16" in enc_list:
            utf16_strings = self._extract_utf16le(data, min_len)
            if utf16_strings:
                all_strings["utf16le"] = utf16_strings

        if "utf16be" in enc_list:
            utf16be = self._extract_utf16be(data, min_len)
            if utf16be:
                all_strings["utf16be"] = utf16be

        total = sum(len(v) for v in all_strings.values())

        return PluginResult(
            module="forensic", plugin="strings_extract", target=target,
            success=True,
            data={
                "strings": all_strings,
                "total_count": total,
                "file_size": len(data),
                "min_length": min_len,
            }
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _extract_ascii(self, data: bytes, min_len: int) -> list[str]:
        pattern = rb"[ -~]{" + str(min_len).encode() + rb",}"
        found = re.findall(pattern, data)
        return [s.decode("ascii") for s in found]

    def _extract_utf16le(self, data: bytes, min_len: int) -> list[str]:
        pattern = rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}"
        found = re.findall(pattern, data)
        return [s.decode("utf-16-le", errors="replace") for s in found]

    def _extract_utf16be(self, data: bytes, min_len: int) -> list[str]:
        pattern = rb"(?:\x00[\x20-\x7e]){" + str(min_len).encode() + rb",}"
        found = re.findall(pattern, data)
        return [s.decode("utf-16-be", errors="replace") for s in found]
