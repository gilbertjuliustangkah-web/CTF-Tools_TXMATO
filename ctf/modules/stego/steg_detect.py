"""
Stego - Steganography Detection Plugin
Detect steganography in images using LSB analysis and metadata.
"""
import math
from ctf.core.plugin import PluginBase, PluginResult, register_plugin


@register_plugin
class StegDetect(PluginBase):
    name = "steg_detect"
    description = "Detect steganography in images: LSB analysis, metadata, file appending"
    category = "stego"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        try:
            with open(target, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return PluginResult(
                module="stego", plugin="steg_detect", target=target,
                success=False, error=f"File not found: {target}"
            )

        findings = []
        file_type = self._detect_type(data)

        if file_type == "PNG":
            findings.extend(self._analyze_png_lsb(data))
            findings.extend(self._check_png_chunks(data))

        findings.extend(self._check_appended_data(data))
        findings.extend(self._check_strings(data))

        return PluginResult(
            module="stego", plugin="steg_detect", target=target,
            success=True,
            data={
                "file_type": file_type,
                "file_size": len(data),
                "findings": findings,
                "finding_count": len(findings),
                "entropy": round(self._entropy(data), 4),
            }
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _detect_type(self, data: bytes) -> str:
        signatures = {
            b"\x89PNG": "PNG",
            b"\xff\xd8\xff": "JPEG",
            b"GIF8": "GIF",
            b"BM": "BMP",
            b"RIFF": "WAV/WEBP",
        }
        for sig, name in signatures.items():
            if data[:len(sig)] == sig:
                return name
        return "Unknown"

    def _analyze_png_lsb(self, data: bytes) -> list[dict]:
        findings = []
        idat_start = data.find(b"IDAT")
        if idat_start == -1:
            return findings

        lsb_bits = []
        pixel_region = data[idat_start:min(idat_start + 100000, len(data))]
        for i in range(0, min(len(pixel_region), 10000) - 3, 4):
            lsb_bits.append(pixel_region[i] & 1)
            lsb_bits.append(pixel_region[i + 1] & 1)
            lsb_bits.append(pixel_region[i + 2] & 1)

        if lsb_bits:
            ones = sum(lsb_bits)
            ratio = ones / len(lsb_bits)
            if 0.35 < ratio < 0.65:
                findings.append({
                    "type": "LSB Analysis",
                    "severity": "medium",
                    "detail": f"LSB distribution ratio: {ratio:.3f} (close to 0.5 suggests LSB stego)",
                })

        return findings

    def _check_png_chunks(self, data: bytes) -> list[dict]:
        findings = []
        known_chunks = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tEXt", b"zTXt", b"iTXt", b"gAMA", b"pHYs"}

        pos = 8
        while pos < len(data) - 12:
            try:
                chunk_len = int.from_bytes(data[pos:pos + 4], "big")
                chunk_type = data[pos + 4:pos + 8]
                if chunk_type not in known_chunks and len(chunk_type) == 4:
                    if all(32 <= b < 127 for b in chunk_type):
                        findings.append({
                            "type": "Custom PNG Chunk",
                            "severity": "info",
                            "detail": f"Unknown chunk: {chunk_type.decode()} at offset {pos}",
                        })
                pos += 12 + chunk_len
            except Exception:
                break
        return findings

    def _check_appended_data(self, data: bytes) -> list[dict]:
        findings = []
        markers = {
            b"PK\x03\x04": "ZIP archive appended",
            b"\x1f\x8b": "GZIP data appended",
            b"Rar!": "RAR archive appended",
            b"7z\xbc\xaf": "7-Zip archive appended",
        }

        for end_marker in [b"IEND", b"\xff\xd9"]:
            idx = data.find(end_marker)
            if idx != -1:
                after = idx + len(end_marker)
                if after < len(data):
                    remaining = data[after:]
                    for sig, desc in markers.items():
                        if remaining[:len(sig)] == sig:
                            findings.append({
                                "type": "Appended Data",
                                "severity": "high",
                                "detail": f"{desc} after image end (offset {after})",
                            })
        return findings

    def _check_strings(self, data: bytes) -> list[dict]:
        findings = []
        interesting = [
            (b"password", "Password string found"),
            (b"secret", "Secret string found"),
            (b"flag{", "Flag pattern found"),
            (b"FLAG{", "Flag pattern found"),
            (b"-----BEGIN", "PEM/base64 data found"),
        ]
        for pattern, desc in interesting:
            if pattern in data:
                idx = data.find(pattern)
                findings.append({
                    "type": "Embedded String",
                    "severity": "info",
                    "detail": f"{desc} at offset {idx}",
                })
        return findings

    def _entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        return -sum((f / n) * math.log2(f / n) for f in freq if f)
