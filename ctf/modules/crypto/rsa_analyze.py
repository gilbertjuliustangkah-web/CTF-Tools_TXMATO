"""
Crypto - RSA Key Analysis Plugin
Pure Python RSA key analysis (without external tools).
"""
import re
from math import gcd
from ctf.core.plugin import PluginBase, PluginResult, register_plugin


@register_plugin
class RsaAnalyze(PluginBase):
    name = "rsa_analyze"
    description = "Analyze RSA keys: extract n, e, d, p, q; check common vulnerabilities"
    category = "crypto"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        data = target.strip()
        result = {
            "n": None, "e": None, "d": None, "p": None, "q": None,
            "key_bits": 0, "is_public_only": True, "vulnerabilities": [],
            "factors": [],
        }

        n_match = re.search(r"[nN]\s*=\s*(\d+)", data)
        e_match = re.search(r"[eE]\s*=\s*(\d+)", data)
        d_match = re.search(r"[dD]\s*=\s*(\d+)", data)
        p_match = re.search(r"[pP]\s*=\s*(\d+)", data)
        q_match = re.search(r"[qQ]\s*=\s*(\d+)", data)

        if n_match:
            result["n"] = int(n_match.group(1))
            result["key_bits"] = result["n"].bit_length()
        if e_match:
            result["e"] = int(e_match.group(1))
        if d_match:
            result["d"] = int(d_match.group(1))
            result["is_public_only"] = False
        if p_match:
            result["p"] = int(p_match.group(1))
        if q_match:
            result["q"] = int(q_match.group(1))

        if result["n"] and result["e"]:
            result["vulnerabilities"] = self._check_vulnerabilities(result)

        return PluginResult(
            module="crypto", plugin="rsa_analyze", target="",
            success=True, data=result
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _check_vulnerabilities(self, key: dict) -> list[str]:
        vulns = []
        n = key["n"]
        e = key["e"]

        if e == 1:
            vulns.append("e=1: trivially breakable")
        if e == 3 and key["key_bits"] < 1024:
            vulns.append("Small e with small n: may be vulnerable to cube root attack")

        if key["p"] and key["q"]:
            phi = (key["p"] - 1) * (key["q"] - 1)
            if gcd(e, phi) != 1:
                vulns.append("e and phi(n) are not coprime — key is invalid")
            if key["p"] == key["q"]:
                vulns.append("p == q: key is trivially breakable")

        if n and n < 10**20:
            vulns.append("Very small n: can be factored with trial division")
        elif n and n < 2**32:
            vulns.append("Small n: vulnerable to factoring (try factordb.com)")

        return vulns
