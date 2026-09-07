"""
Crypto - XOR Tool Plugin
XOR cipher operations: encrypt, decrypt, known-plaintext key recovery.
"""
from ctf.core.plugin import PluginBase, PluginResult, register_plugin


@register_plugin
class XorTool(PluginBase):
    name = "xor_tool"
    description = "XOR cipher: encrypt, decrypt, key recovery from known plaintext"
    category = "crypto"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        mode = kwargs.get("mode", "decrypt")
        key = kwargs.get("key", "")
        known_plain = kwargs.get("known_plain", "")
        known_cipher = kwargs.get("known_cipher", "")

        try:
            if mode == "encrypt":
                return self._encrypt(target, key)
            elif mode == "decrypt":
                return self._decrypt(target, key)
            elif mode == "key_from_plaintext":
                return self._recover_key(known_plain, known_cipher)
            elif mode == "single_byte":
                return self._single_byte_crack(target)
            else:
                return self._decrypt(target, key)
        except Exception as e:
            return PluginResult(
                module="crypto", plugin="xor_tool", target=target,
                success=False, error=str(e)
            )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _to_bytes(self, s: str) -> bytes:
        if all(c in "0123456789abcdefABCDEF" for c in s.replace(" ", "")):
            clean = s.replace(" ", "").replace("0x", "")
            if len(clean) % 2 == 0:
                try:
                    return bytes.fromhex(clean)
                except ValueError:
                    pass
        return s.encode()

    def _encrypt(self, target: str, key: str) -> PluginResult:
        data = self._to_bytes(target)
        key_bytes = self._to_bytes(key)
        result = bytes(d ^ key_bytes[i % len(key_bytes)] for i, d in enumerate(data))
        return PluginResult(
            module="crypto", plugin="xor_tool", target=target,
            success=True,
            data={
                "mode": "encrypt",
                "result_hex": result.hex(),
                "result_b64": __import__("base64").b64encode(result).decode(),
                "result_bytes": result,
            }
        )

    def _decrypt(self, target: str, key: str) -> PluginResult:
        data = self._to_bytes(target)
        key_bytes = self._to_bytes(key)
        result = bytes(d ^ key_bytes[i % len(key_bytes)] for i, d in enumerate(data))
        try:
            text = result.decode("utf-8", errors="replace")
        except Exception:
            text = repr(result)
        return PluginResult(
            module="crypto", plugin="xor_tool", target=target,
            success=True,
            data={
                "mode": "decrypt",
                "result_hex": result.hex(),
                "result_text": text,
                "result_bytes": result,
            }
        )

    def _recover_key(self, known_plain: str, known_cipher: str) -> PluginResult:
        plain = self._to_bytes(known_plain)
        cipher = self._to_bytes(known_cipher)
        if len(plain) != len(cipher):
            return PluginResult(
                module="crypto", plugin="xor_tool", target="",
                success=False,
                error=f"Length mismatch: plain={len(plain)}, cipher={len(cipher)}"
            )
        key = bytes(p ^ c for p, c in zip(plain, cipher))
        return PluginResult(
            module="crypto", plugin="xor_tool", target="",
            success=True,
            data={
                "mode": "key_recovery",
                "key_hex": key.hex(),
                "key_text": key.decode(errors="replace"),
                "key_length": len(key),
            }
        )

    def _single_byte_crack(self, target: str) -> PluginResult:
        data = self._to_bytes(target)
        best = {"score": -1, "key": 0, "text": ""}
        for byte_val in range(256):
            decrypted = bytes(b ^ byte_val for b in data)
            try:
                text = decrypted.decode("ascii", errors="strict")
            except UnicodeDecodeError:
                continue
            score = sum(1 for c in text if c.isalpha() or c in " .,!?")
            if score > best["score"]:
                best = {"score": score, "key": byte_val, "text": text}
        return PluginResult(
            module="crypto", plugin="xor_tool", target=target,
            success=best["score"] > 0,
            data={
                "mode": "single_byte_crack",
                "best_key": best["key"],
                "best_key_hex": f"0x{best['key']:02x}",
                "best_text": best["text"],
                "score": best["score"],
            }
        )
