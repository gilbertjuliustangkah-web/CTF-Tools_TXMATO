"""
Pwn - Cyclic Pattern Plugin
Generates / finds De Bruijn offset patterns (like pwntools cyclic).
"""
from ctf.core.plugin import PluginBase, PluginResult, register_plugin

ALPHABET = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
BLOCK = 4


def _gen(alphabet: bytes, n: int = BLOCK):
    """Yield the FMK De Bruijn sequence over `alphabet` with block size `n`,
    one byte at a time, in generated order (no full allocation)."""
    k = len(alphabet)
    a = [0] * (n + 1)

    def db(t, p):
        if t > n:
            if n % p == 0:
                yield from a[1 : p + 1]
        else:
            a[t] = a[t - p]
            yield from db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                yield from db(t + 1, t)

    for idx in db(1, 1):
        yield alphabet[idx]


def cyclic_bytes(length: int, alphabet: bytes = ALPHABET) -> bytes:
    g = _gen(alphabet)
    return bytes(next(g, 0) for _ in range(max(0, length)))


def cyclic_find(pattern: bytes, alphabet: bytes = ALPHABET) -> int | None:
    """Return the byte offset where `pattern` first appears in the cyclic
    pattern, or None if it does not appear. Matches up to the whole pattern
    (any alignment)."""
    pattern = bytes(pattern)
    if not pattern or not set(pattern).issubset(set(alphabet)):
        return None
    need = len(pattern)
    window = bytearray()
    g = _gen(alphabet)
    for pos in range(1 << 24):
        b = next(g, None)
        if b is None:
            return None
        window.append(b)
        if len(window) > need:
            del window[0]
        if len(window) == need and window == pattern:
            return pos - need + 1
    return None


@register_plugin
class CyclicPattern(PluginBase):
    name = "cyclic"
    description = "Generate/login De Bruijn patterns to find offsets (pwntools cyclic)"
    category = "pwn"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        mode = (kwargs.get("mode") or "generate").strip().lower()
        length = int(kwargs.get("length") or 200)
        pattern = (kwargs.get("pattern") or "").strip()

        if mode in ("find", "offset"):
            if not pattern:
                return PluginResult(
                    module="pwn", plugin="cyclic", target=target,
                    success=False, error="No pattern provided to find."
                )
            # Interpret input: ASCII text first (usual case). Falls back to
            # hex only when the text is pure hex and the ASCII form doesn't
            # match (e.g. raw crashing bytes copied from a debugger).
            ascii_bytes = pattern.encode("utf-8")
            hex_bytes = None
            if pattern.lower().startswith("0x"):
                pattern = pattern[2:]
            if len(pattern) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in pattern):
                try:
                    hex_bytes = bytes.fromhex(pattern)
                except ValueError:
                    hex_bytes = None

            offset = None
            found_in = "ascii"
            candidates = [(ascii_bytes, "ascii")]
            if hex_bytes is not None and hex_bytes != ascii_bytes:
                candidates.append((hex_bytes, "hex"))
            for cand, label in candidates:
                off = cyclic_find(cand)
                if off is not None:
                    offset, found_in = off, label
                    break

            if offset is None:
                return PluginResult(
                    module="pwn", plugin="cyclic", target=target,
                    success=False,
                    error="Pattern not found. Is it a real cyclic-subsequence (ASCII/hex) from this alphabet?",
                )
            data = {
                "mode": "find",
                "pattern": pattern,
                "found_in": found_in,
                "offset": offset,
                "as_le32": None,
                "as_le64": None,
                "as_be32": None,
            }
            data["as_le32"] = f"0x{offset:08x} (LE bytes: {offset.to_bytes(4, 'little').hex()})"
            data["as_le64"] = f"0x{offset:016x} (LE bytes: {offset.to_bytes(8, 'little').hex()})"
            return PluginResult(
                module="pwn", plugin="cyclic", target=target,
                success=True, data=data
            )

        # Generate mode
        if length < 0 or length > 10_000_000:
            return PluginResult(
                module="pwn", plugin="cyclic", target=target,
                success=False, error="Length out of range (0..10,000,000)."
            )
        pattern = cyclic_bytes(length)
        data = {
            "mode": "generate",
            "length": length,
            "pattern": pattern.decode("ascii"),
            "preview": pattern[:96].decode("ascii"),
        }
        return PluginResult(
            module="pwn", plugin="cyclic", target=target,
            success=True, data=data
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}