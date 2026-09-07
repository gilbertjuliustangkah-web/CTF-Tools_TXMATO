"""
Crypto - Frequency Analysis Plugin
Letter frequency analysis for classical cipher breaking.
"""
import string
from collections import Counter
from ctf.core.plugin import PluginBase, PluginResult, register_plugin


@register_plugin
class FreqAnalysis(PluginBase):
    name = "freq_analysis"
    description = "Letter frequency analysis for classical ciphers (Caesar, substitution, Vigenere)"
    category = "crypto"

    ENGLISH_FREQ = {
        'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 12.7, 'f': 2.2,
        'g': 2.0, 'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0,
        'm': 2.4, 'n': 6.7, 'o': 7.5, 'p': 1.9, 'q': 0.095, 'r': 6.0,
        's': 6.3, 't': 9.1, 'u': 2.8, 'v': 0.98, 'w': 2.4, 'x': 0.15,
        'y': 2.0, 'z': 0.074,
    }

    async def execute(self, target: str, **kwargs) -> PluginResult:
        text = target.lower()
        letters = [c for c in text if c in string.ascii_lowercase]
        total = len(letters)

        if total == 0:
            return PluginResult(
                module="crypto", plugin="freq_analysis", target=target,
                success=False, error="No letters found in input"
            )

        freq = Counter(letters)
        freq_pct = {ch: round((freq.get(ch, 0) / total) * 100, 2) for ch in string.ascii_lowercase}

        sorted_actual = sorted(freq_pct.items(), key=lambda x: x[1], reverse=True)
        sorted_english = sorted(self.ENGLISH_FREQ.items(), key=lambda x: x[1], reverse=True)

        likely_caesar_shift = self._guess_caesar_shift(sorted_actual, sorted_english)

        chi_squared = sum(
            ((freq_pct[ch] - self.ENGLISH_FREQ[ch]) ** 2) / max(self.ENGLISH_FREQ[ch], 0.001)
            for ch in string.ascii_lowercase
        )

        return PluginResult(
            module="crypto", plugin="freq_analysis", target=target,
            success=True,
            data={
                "frequency": freq_pct,
                "letter_count": total,
                "unique_letters": len(freq),
                "top_5": sorted_actual[:5],
                "bottom_5": sorted_actual[-5:],
                "english_comparison": sorted_english[:5],
                "likely_caesar_shift": likely_caesar_shift,
                "chi_squared": round(chi_squared, 2),
                "note": "Lower chi-squared = more English-like distribution",
            }
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _guess_caesar_shift(self, actual: list, english: list) -> int:
        if not actual or not english:
            return 0
        most_frequent_cipher = actual[0][0]
        most_frequent_english = english[0][0]
        shift = (ord(most_frequent_cipher) - ord(most_frequent_english)) % 26
        return shift
