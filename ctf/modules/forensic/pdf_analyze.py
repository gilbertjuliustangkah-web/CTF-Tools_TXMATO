"""
Forensic - PDF Analysis Plugin
Pure Python PDF structure analysis and metadata extraction.
"""
import re
from ctf.core.plugin import PluginBase, PluginResult, register_plugin


@register_plugin
class PdfAnalyze(PluginBase):
    name = "pdf_analyze"
    description = "Analyze PDF files: metadata, structure, embedded files, JavaScript, actions"
    category = "forensic"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        try:
            with open(target, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return PluginResult(
                module="forensic", plugin="pdf_analyze", target=target,
                success=False, error=f"File not found: {target}"
            )
        except PermissionError:
            return PluginResult(
                module="forensic", plugin="pdf_analyze", target=target,
                success=False, error=f"Permission denied: {target}"
            )

        if not data[:5] == b"%PDF-":
            return PluginResult(
                module="forensic", plugin="pdf_analyze", target=target,
                success=False, error="Not a valid PDF file"
            )

        info = self._parse_pdf(data)
        return PluginResult(
            module="forensic", plugin="pdf_analyze", target=target,
            success=True, data=info
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _parse_pdf(self, data: bytes) -> dict:
        result = {
            "file_size": len(data),
            "pdf_version": self._extract_version(data),
            "objects": [],
            "pages": 0,
            "has_javascript": False,
            "has_embedded_files": False,
            "has_launch_action": False,
            "has_suspicious_actions": False,
            "metadata": {},
            "warnings": [],
        }

        obj_pattern = re.compile(rb"(\d+)\s+(\d+)\s+obj")
        result["objects"] = [{"id": int(m.group(1)), "gen": int(m.group(2))}
                            for m in obj_pattern.finditer(data)]

        page_count = re.findall(rb"/Type\s*/Page[^s]", data)
        result["pages"] = len(page_count)

        if re.search(rb"/JavaScript|/JS\s", data):
            result["has_javascript"] = True
            result["warnings"].append("PDF contains JavaScript")

        if re.search(rb"/EmbeddedFiles|/EmbeddedFile", data):
            result["has_embedded_files"] = True
            result["warnings"].append("PDF contains embedded files")

        if re.search(rb"/Launch|/Action", data):
            result["has_launch_action"] = True
            result["warnings"].append("PDF contains launch/action triggers")

        if re.search(rb"/OpenAction|/AA\s", data):
            result["has_suspicious_actions"] = True
            result["warnings"].append("PDF has auto-open actions")

        meta = {}
        title = re.search(rb"/Title\s*\(([^)]+)\)", data)
        author = re.search(rb"/Author\s*\(([^)]+)\)", data)
        creator = re.search(rb"/Creator\s*\(([^)]+)\)", data)
        producer = re.search(rb"/Producer\s*\(([^)]+)\)", data)

        if title:
            meta["title"] = title.group(1).decode(errors="replace")
        if author:
            meta["author"] = author.group(1).decode(errors="replace")
        if creator:
            meta["creator"] = creator.group(1).decode(errors="replace")
        if producer:
            meta["producer"] = producer.group(1).decode(errors="replace")

        result["metadata"] = meta
        return result

    def _extract_version(self, data: bytes) -> str:
        m = re.match(rb"%PDF-(\d+\.\d+)", data)
        return m.group(1).decode() if m else "unknown"
