"""
Web - JWT Decode Plugin
Decode and verify JWT tokens (pure Python, no external deps).
"""
import base64
import json
from ctf.core.plugin import PluginBase, PluginResult, register_plugin


@register_plugin
class JwtDecode(PluginBase):
    name = "jwt_decode"
    description = "Decode JWT tokens: header, payload, signature, expiry check"
    category = "web"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        token = target.strip()
        parts = token.split(".")
        if len(parts) < 2 or len(parts) > 3:
            return PluginResult(
                module="web", plugin="jwt_decode", target="",
                success=False, error="Invalid JWT format. Expected header.payload[.signature]"
            )

        header = self._decode_part(parts[0])
        payload = self._decode_part(parts[1])
        signature = parts[2] if len(parts) == 3 else None

        warnings = self._check_weak(header, payload)

        return PluginResult(
            module="web", plugin="jwt_decode", target="",
            success=True,
            data={
                "header": header,
                "payload": payload,
                "signature": signature,
                "parts": len(parts),
                "warnings": warnings,
                "raw_token": token[:80] + "..." if len(token) > 80 else token,
            }
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _decode_part(self, part: str) -> dict:
        padded = part + "=" * (4 - len(part) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded)
        except Exception:
            try:
                return {"raw_text": decoded.decode(errors="replace")}
            except Exception:
                return {"raw_b64": part}

    def _check_weak(self, header: dict, payload: dict) -> list[str]:
        warnings = []
        alg = header.get("alg", "")
        if alg == "none":
            warnings.append("CRITICAL: alg=none — signature is not verified, token is forgeable")
        elif alg in ("HS256", "HS384", "HS512"):
            warnings.append("HMAC-based algorithm — vulnerable to key brute-force if key is weak")
        elif alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
            pass  # Asymmetric — generally safe if key is strong

        exp = payload.get("exp")
        if exp:
            import time
            now = time.time()
            if exp < now:
                warnings.append(f"Token EXPIRED ({int(now - exp)}s ago)")
            elif exp - now < 3600:
                warnings.append(f"Token expires soon ({int(exp - now)}s)")

        if payload.get("admin") is True or payload.get("role") == "admin":
            warnings.append("Payload contains admin claim")

        return warnings
