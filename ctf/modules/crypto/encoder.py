"""
Crypto - Encoding / Decoding / Hash identification plugin
Pure Python, no external tools needed.
"""
import base64
import binascii
import hashlib
import re
import urllib.parse
from ctf.core.plugin import PluginBase, PluginResult, register_plugin


@register_plugin
class EncoderPlugin(PluginBase):
    name = "encode"
    description = "Encode/decode: base64, hex, binary, URL, ROT13"
    category = "crypto"

    async def execute(self, target: str, mode: str = "detect", **kwargs) -> PluginResult:
        """
        target = the string to operate on
        mode   = detect | b64enc | b64dec | hexenc | hexdec |
                 binenc | bindec | urlenc | urldec | rot13
        """
        ops = {
            "b64enc": self._b64enc,
            "b64dec": self._b64dec,
            "hexenc": self._hexenc,
            "hexdec": self._hexdec,
            "binenc": self._binenc,
            "bindec": self._bindec,
            "urlenc": self._urlenc,
            "urldec": self._urldec,
            "rot13":  self._rot13,
            "detect": self._detect,
        }
        fn = ops.get(mode, self._detect)
        try:
            data = fn(target)
            return PluginResult(
                module="crypto", plugin="encode", target=target,
                success=True, data=data
            )
        except Exception as e:
            return PluginResult(
                module="crypto", plugin="encode", target=target,
                success=False, error=str(e)
            )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    # ── Operations ──────────────────────────────────────────────────────────

    def _b64enc(self, s: str) -> dict:
        return {"mode": "base64_encode", "result": base64.b64encode(s.encode()).decode()}

    def _b64dec(self, s: str) -> dict:
        return {"mode": "base64_decode", "result": base64.b64decode(s).decode(errors="replace")}

    def _hexenc(self, s: str) -> dict:
        return {"mode": "hex_encode", "result": s.encode().hex()}

    def _hexdec(self, s: str) -> dict:
        return {"mode": "hex_decode", "result": bytes.fromhex(s).decode(errors="replace")}

    def _binenc(self, s: str) -> dict:
        b = " ".join(format(ord(c), "08b") for c in s)
        return {"mode": "binary_encode", "result": b}

    def _bindec(self, s: str) -> dict:
        parts = s.strip().split()
        result = "".join(chr(int(p, 2)) for p in parts)
        return {"mode": "binary_decode", "result": result}

    def _urlenc(self, s: str) -> dict:
        return {"mode": "url_encode", "result": urllib.parse.quote(s)}

    def _urldec(self, s: str) -> dict:
        return {"mode": "url_decode", "result": urllib.parse.unquote(s)}

    def _rot13(self, s: str) -> dict:
        result = s.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        ))
        return {"mode": "rot13", "result": result}

    def _detect(self, s: str) -> dict:
        """Try to auto-detect encoding and decode."""
        results = {}

        # Base64?
        try:
            dec = base64.b64decode(s + "==").decode(errors="replace")
            if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in dec):
                results["base64"] = dec
        except Exception:
            pass

        # Hex?
        clean = s.replace(" ", "").replace("0x", "")
        if re.fullmatch(r"[0-9a-fA-F]+", clean) and len(clean) % 2 == 0:
            try:
                results["hex"] = bytes.fromhex(clean).decode(errors="replace")
            except Exception:
                pass

        # Binary?
        if re.fullmatch(r"[01 ]+", s):
            try:
                parts = s.strip().split()
                results["binary"] = "".join(chr(int(p, 2)) for p in parts)
            except Exception:
                pass

        # URL encoded?
        if "%" in s:
            results["url"] = urllib.parse.unquote(s)

        # Hash identification
        results["hash_hints"] = self._identify_hash(s)

        return {"mode": "detect", "detections": results}

    def _identify_hash(self, s: str) -> list[str]:
        hints = []
        s = s.strip()
        length_map = {
            32: ["MD5", "NTLM"],
            40: ["SHA-1"],
            56: ["SHA-224"],
            64: ["SHA-256"],
            96: ["SHA-384"],
            128: ["SHA-512"],
        }
        if re.fullmatch(r"[0-9a-fA-F]+", s):
            hints = length_map.get(len(s), ["Unknown hash"])
        if s.startswith("$2"):
            hints = ["bcrypt"]
        return hints
