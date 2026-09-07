"""
Crypto - Caesar / ROT Brute Force Plugin
Brute-force all 26 Caesar cipher shifts with English frequency scoring.
"""
import re
import string
from collections import Counter
from ctf.core.plugin import PluginBase, PluginResult, register_plugin


@register_plugin
class CaesarBrute(PluginBase):
    name = "caesar_brute"
    description = "Brute-force Caesar/ROT cipher (all 26 shifts) with scoring"
    category = "crypto"

    LETTER_FREQ = {
        'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 12.7, 'f': 2.2,
        'g': 2.0, 'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0,
        'm': 2.4, 'n': 6.7, 'o': 7.5, 'p': 1.9, 'q': 0.095, 'r': 6.0,
        's': 6.3, 't': 9.1, 'u': 2.8, 'v': 0.98, 'w': 2.4, 'x': 0.15,
        'y': 2.0, 'z': 0.074,
    }

    COMMON_WORDS = (
        r"the|and|that|have|with|this|from|they|your|what|when|"
        r"hello|world|flag|flag\{|ctf|attack|defend|testing|cipher|"
        r"secret|message|which|there|their|about|would|these|"
        r"into|them|than|were|time|been|will|more|some|other"
    )

    async def execute(self, target: str, **kwargs) -> PluginResult:
        shift = kwargs.get("shift")
        results = []

        if shift is not None and int(shift) >= 0:
            shift = int(shift) % 26
            decoded = self._caesar(target, shift)
            results.append({
                "shift": shift,
                "text": decoded,
                "score": self._english_score(decoded),
            })
        else:
            for s in range(26):
                decoded = self._caesar(target, s)
                results.append({
                    "shift": s,
                    "text": decoded,
                    "score": round(self._english_score(decoded), 2),
                })

            results.sort(key=lambda x: x["score"], reverse=True)

        return PluginResult(
            module="crypto", plugin="caesar_brute", target=target,
            success=True,
            data={
                "results": results,
                "best_shift": results[0]["shift"] if results else None,
                "best_text": results[0]["text"] if results else None,
                "total_shifts": len(results),
            }
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _caesar(self, text: str, shift: int) -> str:
        result = []
        for c in text:
            if c in string.ascii_lowercase:
                result.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
            elif c in string.ascii_uppercase:
                result.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
            else:
                result.append(c)
        return "".join(result)

    def _english_score(self, text: str) -> float:
        freq = Counter(c.lower() for c in text if c.isalpha())
        total = sum(freq.values()) or 1
        score = 0.0
        for letter, count in freq.items():
            observed = (count / total) * 100
            expected = self.LETTER_FREQ.get(letter, 0)
            score += min(observed, expected) * (1 + expected / 100)
        words = re.findall(rf"\b(?:{self.COMMON_WORDS})\b", text.lower())
        score += len(words) * 8.0
        return round(score, 2)
