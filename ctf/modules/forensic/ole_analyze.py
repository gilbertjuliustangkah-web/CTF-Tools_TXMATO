"""
Forensic - OLE/Office Document Analysis Plugin
Analyzes OLE/Office files for macros, metadata, and suspicious content.
Falls back to pure Python if oletools is not installed.
"""
import re
from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core.process import run, is_available


@register_plugin
class OleAnalyze(PluginBase):
    name = "ole_analyze"
    description = "Analyze Office documents: OLE macros, metadata, streams, suspicious patterns"
    category = "forensic"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        try:
            with open(target, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return PluginResult(
                module="forensic", plugin="ole_analyze", target=target,
                success=False, error=f"File not found: {target}"
            )
        except PermissionError:
            return PluginResult(
                module="forensic", plugin="ole_analyze", target=target,
                success=False,                 error=f"Permission denied: {target}"
            )

        info = self._analyze(data, target)
        return PluginResult(
            module="forensic", plugin="ole_analyze", target=target,
            success=True, data=info
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _analyze(self, data: bytes, target: str) -> dict:
        result = {
            "file_size": len(data),
            "is_ole": False,
            "is_office_xml": False,
            "streams": [],
            "has_macros": False,
            "macro_indicators": [],
            "metadata": {},
            "suspicious_patterns": [],
        }

        if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            result["is_ole"] = True
            result["streams"] = self._find_ole_streams(data)
        elif b"[Content_Types].xml" in data or b"word/" in data.lower():
            result["is_office_xml"] = True

        vba_patterns = [
            rb"VBA_PROJECT",
            rb"Microsoft Visual Basic",
            rb"Sub\s+\w+\(",
            rb"Shell\s*\(",
            rb"CreateObject\s*\(",
            rb"WScript\.Shell",
            rb"PowerShell",
            rb"cmd\.exe",
            rb"/c\s+",
            rb"Auto_Open",
            rb"Document_Open",
            rb"Workbook_Open",
        ]
        for pat in vba_patterns:
            if re.search(pat, data, re.IGNORECASE):
                result["has_macros"] = True
                result["macro_indicators"].append(pat.decode(errors="replace"))

        suspicious = [
            (rb"http[s]?://", "External URL reference"),
            (rb"\\\\[^\s]+", "UNC path (network share)"),
            (rb"eval\s*\(", "eval() call"),
            (rb"exec\s*\(", "exec() call"),
            (rb"base64", "Base64 encoding"),
            (rb"<script", "HTML/Script tag"),
        ]
        for pat, desc in suspicious:
            if re.search(pat, data, re.IGNORECASE):
                result["suspicious_patterns"].append(desc)

        meta = {}
        for pattern, key in [
            (rb"\x05Title([^\x00]+)", "title"),
            (rb"\x05Subject([^\x00]+)", "subject"),
            (rb"\x05Author([^\x00]+)", "author"),
            (rb"\x05Creator([^\x00]+)", "creator"),
        ]:
            m = re.search(pattern, data)
            if m:
                meta[key] = m.group(1).decode(errors="replace").strip()
        result["metadata"] = meta

        return result

    def _find_ole_streams(self, data: bytes) -> list[str]:
        streams = []
        known = [b"WordDocument", b"1Table", b"0Table", b"Macros", b"_VBA_PROJECT"]
        for name in known:
            if name in data:
                streams.append(name.decode())
        return streams
