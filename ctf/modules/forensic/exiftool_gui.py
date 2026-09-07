"""
Forensic - ExifTool Web GUI Plugin
Full metadata viewer/editor wrapping exiftool with structured JSON output.
"""
import json
from pathlib import Path
from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core.process import run, is_available
from ctf.core import workspace as ws_util


@register_plugin
class ExiftoolGui(PluginBase):
    name = "exiftool_gui"
    description = "ExifTool GUI: view, edit, delete metadata tags from files"
    category = "forensic"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        sandbox = kwargs.get("sandbox")
        mode = kwargs.get("mode", "read")
        tag_name = kwargs.get("tag_name", "")
        tag_value = kwargs.get("tag_value", "")

        path = self._resolve_path(target, sandbox)
        if isinstance(path, PluginResult):
            return path

        if not path.exists():
            return PluginResult(
                module="forensic", plugin="exiftool_gui", target=target,
                success=False, error=f"File not found: {target}"
            )

        if not is_available("exiftool"):
            return self._fallback_read(path, target)

        if mode == "read":
            return await self._read_tags(path, target)
        elif mode == "edit":
            return await self._edit_tag(path, target, tag_name, tag_value)
        elif mode == "delete":
            return await self._delete_tag(path, target, tag_name)
        elif mode == "export_json":
            return await self._export_json(path, target)
        elif mode == "export_csv":
            return await self._export_csv(path, target)
        else:
            return await self._read_tags(path, target)

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _resolve_path(self, target: str, sandbox):
        raw_path = Path(target)
        if sandbox:
            if isinstance(sandbox, str):
                root = ws_util.resolve_workspace_path(sandbox)
            else:
                root = Path(sandbox).resolve()
            candidate = raw_path.expanduser()
            if not candidate.is_absolute():
                candidate = root / candidate
            candidate = candidate.resolve()
            if not candidate.is_relative_to(root):
                return PluginResult(
                    module="forensic", plugin="exiftool_gui", target=target,
                    success=False,
                    error=f"Access denied: '{target}' is outside the workspace. Copy the file into the workspace first."
                )
            return candidate
        return raw_path

    async def _read_tags(self, path: Path, target: str) -> PluginResult:
        result = await run("exiftool", "-json", "-G", str(path), timeout=30)
        if not result.ok:
            return PluginResult(
                module="forensic", plugin="exiftool_gui", target=target,
                success=False, error=result.stderr or "exiftool failed"
            )

        try:
            json_data = json.loads(result.stdout)
            tags = json_data[0] if json_data else {}
        except (json.JSONDecodeError, IndexError):
            tags = {"Raw": result.stdout}

        groups = {}
        for key, value in tags.items():
            if key.startswith("SourceFile") or key.startswith("ExifTool"):
                continue
            group = key.split(":")[0] if ":" in key else "General"
            tag_key = key.split(":", 1)[1] if ":" in key else key
            if group not in groups:
                groups[group] = []
            groups[group].append({"key": tag_key, "value": str(value), "full_key": key})

        return PluginResult(
            module="forensic", plugin="exiftool_gui", target=target,
            success=True,
            data={
                "path": str(path),
                "groups": groups,
                "total_tags": sum(len(v) for v in groups.values()),
                "filename": path.name,
            }
        )

    async def _edit_tag(self, path: Path, target: str, tag_name: str, tag_value: str) -> PluginResult:
        if not tag_name:
            return PluginResult(
                module="forensic", plugin="exiftool_gui", target=target,
                success=False, error="No tag name specified"
            )

        result = await run(
            "exiftool", f"-{tag_name}={tag_value}", "-overwrite_original", str(path),
            timeout=30
        )
        if result.ok:
            return PluginResult(
                module="forensic", plugin="exiftool_gui", target=target,
                success=True,
                data={"action": "edit", "tag": tag_name, "value": tag_value, "output": result.stdout}
            )
        return PluginResult(
            module="forensic", plugin="exiftool_gui", target=target,
            success=False, error=result.stderr or "Failed to edit tag"
        )

    async def _delete_tag(self, path: Path, target: str, tag_name: str) -> PluginResult:
        if not tag_name:
            return PluginResult(
                module="forensic", plugin="exiftool_gui", target=target,
                success=False, error="No tag name specified"
            )

        result = await run(
            "exiftool", f"-{tag_name}=", "-overwrite_original", str(path),
            timeout=30
        )
        if result.ok:
            return PluginResult(
                module="forensic", plugin="exiftool_gui", target=target,
                success=True,
                data={"action": "delete", "tag": tag_name, "output": result.stdout}
            )
        return PluginResult(
            module="forensic", plugin="exiftool_gui", target=target,
            success=False, error=result.stderr or "Failed to delete tag"
        )

    async def _export_json(self, path: Path, target: str) -> PluginResult:
        result = await run("exiftool", "-json", "-G", str(path), timeout=30)
        if result.ok:
            return PluginResult(
                module="forensic", plugin="exiftool_gui", target=target,
                success=True,
                data={"export_format": "json", "content": result.stdout}
            )
        return PluginResult(
            module="forensic", plugin="exiftool_gui", target=target,
            success=False, error=result.stderr
        )

    async def _export_csv(self, path: Path, target: str) -> PluginResult:
        result = await run("exiftool", "-csv", "-G", str(path), timeout=30)
        if result.ok:
            return PluginResult(
                module="forensic", plugin="exiftool_gui", target=target,
                success=True,
                data={"export_format": "csv", "content": result.stdout}
            )
        return PluginResult(
            module="forensic", plugin="exiftool_gui", target=target,
            success=False, error=result.stderr
        )

    def _fallback_read(self, path: Path, target: str) -> PluginResult:
        """Read basic metadata without exiftool using pure Python."""
        stat = path.stat()
        groups = {"File": [
            {"key": "FileName", "value": path.name, "full_key": "File:FileName"},
            {"key": "FileSize", "value": self._human_size(stat.st_size), "full_key": "File:FileSize"},
            {"key": "FileModifyDate", "value": str(stat.st_mtime), "full_key": "File:FileModifyDate"},
        ]}

        magic_map = {
            b"\x89PNG": [("ImageWidth", "?"), ("ImageHeight", "?"), ("FileType", "PNG")],
            b"\xff\xd8\xff": [("FileType", "JPEG"), ("MIMEType", "image/jpeg")],
            b"GIF8": [("FileType", "GIF"), ("MIMEType", "image/gif")],
            b"%PDF": [("FileType", "PDF"), ("MIMEType", "application/pdf")],
        }
        try:
            with open(path, "rb") as f:
                header = f.read(8)
            for sig, attrs in magic_map.items():
                if header[:len(sig)] == sig:
                    groups["Detected"] = [
                        {"key": k, "value": v, "full_key": f"Detected:{k}"}
                        for k, v in attrs
                    ]
                    break
        except Exception:
            pass

        return PluginResult(
            module="forensic", plugin="exiftool_gui", target=target,
            success=True,
            data={
                "path": str(path),
                "groups": groups,
                "total_tags": sum(len(v) for v in groups.values()),
                "filename": path.name,
                "fallback_mode": True,
                "note": "exiftool not available — showing basic metadata only",
            }
        )

    def _human_size(self, n: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"
