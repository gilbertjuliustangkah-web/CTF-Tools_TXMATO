"""
Crypto - Hash Identifier Plugin
Identify hash types by length, pattern, and known prefixes.
"""
import re
from ctf.core.plugin import PluginBase, PluginResult, register_plugin


@register_plugin
class HashIdentifier(PluginBase):
    name = "hash_id"
    description = "Identify hash types by length, character set, and prefix patterns"
    category = "crypto"

    HASH_DB = [
        {"name": "MD5", "length": 32, "charset": "hex"},
        {"name": "NTLM", "length": 32, "charset": "hex"},
        {"name": "LM", "length": 32, "charset": "hex_upper"},
        {"name": "MD4", "length": 32, "charset": "hex"},
        {"name": "MD5crypt ($1$)", "length": None, "pattern": r"^\$1\$"},
        {"name": "SHA-1", "length": 40, "charset": "hex"},
        {"name": "SHA-1 (Base64)", "length": 28, "charset": "b64"},
        {"name": "SHA-224", "length": 56, "charset": "hex"},
        {"name": "SHA-256", "length": 64, "charset": "hex"},
        {"name": "SHA-384", "length": 96, "charset": "hex"},
        {"name": "SHA-512", "length": 128, "charset": "hex"},
        {"name": "SHA-512/224", "length": 56, "charset": "hex"},
        {"name": "SHA-512/256", "length": 64, "charset": "hex"},
        {"name": "SHA3-224", "length": 56, "charset": "hex"},
        {"name": "SHA3-256", "length": 64, "charset": "hex"},
        {"name": "SHA3-384", "length": 96, "charset": "hex"},
        {"name": "SHA3-512", "length": 128, "charset": "hex"},
        {"name": "bcrypt", "length": None, "pattern": r"^\$2[aby]?\$\d{2}\$"},
        {"name": "scrypt", "length": None, "pattern": r"^\$scrypt\$"},
        {"name": "Argon2i", "length": None, "pattern": r"^\$argon2i\$"},
        {"name": "Argon2d", "length": None, "pattern": r"^\$argon2d\$"},
        {"name": "Argon2id", "length": None, "pattern": r"^\$argon2id\$"},
        {"name": "MD5 (WordPress)", "length": None, "pattern": r"^\$P\$"},
        {"name": "phpBB3", "length": None, "pattern": r"^\$H\$"},
        {"name": "DES (Unix)", "length": 13, "charset": "des"},
        {"name": "LM (Windows)", "length": 32, "charset": "hex_upper"},
        {"name": "NetNTLMv1", "length": None, "pattern": r"^[0-9a-f]{32}:[0-9a-f]{32}:[0-9a-f]+"},
        {"name": "NetNTLMv2", "length": None, "pattern": r"^[0-9a-f]{32}:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+"},
        {"name": "MySQL 4.1+", "length": 40, "charset": "hex_star"},
        {"name": "CRC32", "length": 8, "charset": "hex"},
        {"name": "Adler-32", "length": 8, "charset": "hex"},
    ]

    async def execute(self, target: str, **kwargs) -> PluginResult:
        h = target.strip()
        candidates = []

        for entry in self.HASH_DB:
            if entry.get("pattern"):
                if re.match(entry["pattern"], h):
                    candidates.append(entry["name"])
            elif entry.get("length") and len(h) == entry["length"]:
                if self._matches_charset(h, entry.get("charset", "hex")):
                    candidates.append(entry["name"])

        if not candidates:
            candidates = ["Unknown"]

        return PluginResult(
            module="crypto", plugin="hash_id", target=target,
            success=True,
            data={
                "hash": h,
                "length": len(h),
                "candidates": candidates,
                "is_hex": bool(re.fullmatch(r"[0-9a-fA-F]+", h)),
            }
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _matches_charset(self, s: str, charset: str) -> bool:
        if charset == "hex":
            return bool(re.fullmatch(r"[0-9a-fA-F]+", s))
        elif charset == "hex_upper":
            return bool(re.fullmatch(r"[0-9A-F]+", s))
        elif charset == "hex_star":
            return bool(re.fullmatch(r"[0-9a-fA-F*]+", s))
        elif charset == "b64":
            return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", s))
        elif charset == "des":
            return bool(re.fullmatch(r"[A-Za-z0-9./]+", s))
        return True
