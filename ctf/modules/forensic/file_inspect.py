"""
Forensic - File Inspector Plugin
Extracts metadata, magic bytes, strings from a file.
"""
import os
import platform
import re
import shutil
import struct
from pathlib import Path
from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core.process import run
from ctf.core import workspace as ws_util

# Common magic bytes → file type
MAGIC_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG Image"),
    (b"\xff\xd8\xff",       "JPEG Image"),
    (b"GIF87a",             "GIF Image"),
    (b"GIF89a",             "GIF Image"),
    (b"PK\x03\x04",        "ZIP Archive"),
    (b"PK\x05\x06",        "ZIP Archive (empty)"),
    (b"\x1f\x8b",          "Gzip Archive"),
    (b"BZh",               "Bzip2 Archive"),
    (b"\xfd7zXZ\x00",      "XZ Archive"),
    (b"7z\xbc\xaf'\x1c",   "7-Zip Archive"),
    (b"Rar!\x1a\x07",      "RAR Archive"),
    (b"\x7fELF",           "ELF Binary"),
    (b"MZ",                "PE/Windows Executable"),
    (b"%PDF",              "PDF Document"),
    (b"RIFF",              "RIFF (WAV/AVI)"),
    (b"ID3",               "MP3 Audio"),
    (b"\xff\xfb",          "MP3 Audio"),
    (b"OggS",              "OGG Audio"),
    (b"\x00\x00\x00\x0cftyp", "MP4 Video"),
    (b"\x1a\x45\xdf\xa3",  "MKV/WebM Video"),
    (b"SQLite format 3",   "SQLite Database"),
]


@register_plugin
class FileInspector(PluginBase):
    name = "file_inspect"
    description = "Inspect file: magic bytes, metadata, strings, hex preview"
    category = "forensic"

    def _get_exiftool_cmd(self):
        """Get the exiftool command, using WSL on Windows if available."""
        if platform.system() == "Windows":
            if shutil.which("wsl"):
                try:
                    import subprocess
                    result = subprocess.run(["wsl", "-d", "kali-linux", "--", "which", "exiftool"],
                                          capture_output=True, timeout=30)
                    if result.returncode == 0:
                        return ["wsl", "-d", "kali-linux", "--", "exiftool"]
                except Exception:
                    pass
        return ["exiftool"]

    def _to_wsl_path(self, path: Path) -> str:
        """Convert Windows path to WSL path."""
        if platform.system() == "Windows":
            path_str = str(path.resolve())
            if len(path_str) >= 2 and path_str[1] == ':':
                drive = path_str[0].lower()
                rest = path_str[2:].replace('\\', '/')
                return f"/mnt/{drive}{rest}"
        return str(path)

    async def execute(self, target: str, **kwargs) -> PluginResult:
        # Web-facing inspection is sandboxed to the current workspace so the
        # endpoint cannot be abused to read arbitrary files on the host.
        # kwarg `sandbox` may be a workspace name (str) or a Path root.
        sandbox = kwargs.get("sandbox")

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
                    module="forensic", plugin="file_inspect", target=target,
                    success=False,
                    error=(
                        f"Access denied: '{target}' is outside the current "
                        f"workspace directory '{root}'. Copy the file into the "
                        "workspace folder first."
                    )
                )
            path = candidate
        else:
            path = raw_path

        if not path.exists():
            return PluginResult(
                module="forensic", plugin="file_inspect", target=target,
                success=False, error=f"File not found: {target}"
            )

        data = {}
        data["path"] = str(path.resolve())
        data["size_bytes"] = path.stat().st_size
        data["size_human"] = self._human_size(data["size_bytes"])

        raw = path.read_bytes()

        # Magic bytes detection
        data["file_type"] = self._detect_magic(raw)

        # Hex preview (first 64 bytes)
        data["hex_preview"] = raw[:64].hex(" ")

        # Entropy (simple)
        data["entropy"] = round(self._entropy(raw), 4)

        # Strings extraction
        data["strings"] = self._extract_strings(raw)

        # Exiftool if available
        exiftool_cmd = self._get_exiftool_cmd()
        if exiftool_cmd != ["exiftool"] or shutil.which("exiftool"):
            exiftool_path = self._to_wsl_path(path) if exiftool_cmd[0] == "wsl" else str(path)
            result = await run(*exiftool_cmd, exiftool_path, timeout=15)
            if result.ok:
                data["exiftool"] = result.stdout

        return PluginResult(
            module="forensic", plugin="file_inspect", target=target,
            success=True, data=data
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _detect_magic(self, raw: bytes) -> str:
        for sig, name in MAGIC_SIGNATURES:
            if raw[:len(sig)] == sig or raw[4:4+len(sig)] == sig:
                return name
        return "Unknown / Data"

    def _human_size(self, n: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    def _entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        import math
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        return -sum((f / n) * math.log2(f / n) for f in freq if f)

    def _extract_strings(self, data: bytes, min_len: int = 4) -> list[str]:
        pattern = rb"[ -~]{" + str(min_len).encode() + rb",}"
        found = re.findall(pattern, data)
        strings = [s.decode() for s in found]
        # Deduplicate, keep first 100
        seen = set()
        result = []
        for s in strings:
            if s not in seen:
                seen.add(s)
                result.append(s)
            if len(result) >= 100:
                break
        return result
