"""
Forensic - Hash Calculator Plugin
Pure Python file hashing (MD5, SHA1, SHA256, SHA512, etc.)
"""
import hashlib
from ctf.core.plugin import PluginBase, PluginResult, register_plugin


@register_plugin
class HashCalc(PluginBase):
    name = "hash_calc"
    description = "Calculate file hashes: MD5, SHA1, SHA224, SHA256, SHA384, SHA512"
    category = "forensic"

    ALGORITHMS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512"]

    async def execute(self, target: str, **kwargs) -> PluginResult:
        algorithms = kwargs.get("algorithms", ",".join(self.ALGORITHMS))
        algo_list = [a.strip().lower() for a in algorithms.split(",")]

        try:
            with open(target, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return PluginResult(
                module="forensic", plugin="hash_calc", target=target,
                success=False, error=f"File not found: {target}"
            )
        except PermissionError:
            return PluginResult(
                module="forensic", plugin="hash_calc", target=target,
                success=False, error=f"Permission denied: {target}"
            )

        hashes = {}
        for algo in algo_list:
            if algo not in self.ALGORITHMS:
                continue
            try:
                h = hashlib.new(algo)
                h.update(data)
                hashes[algo] = h.hexdigest()
            except Exception:
                continue

        return PluginResult(
            module="forensic", plugin="hash_calc", target=target,
            success=True,
            data={
                "hashes": hashes,
                "file_size": len(data),
                "filename": target,
            }
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}
