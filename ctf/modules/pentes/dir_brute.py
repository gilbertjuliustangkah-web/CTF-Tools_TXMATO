"""
Pentest - HTTP Directory Brute-Forcing Plugin

Enumerates web paths on a target. Uses ffuf/gobuster when available, otherwise
a lightweight pure-Python concurrent GET-based scanner with a built-in wordlist
(short, safe, low-signal). URL is validated and never passed through a shell.
"""
import asyncio
import re

import httpx

from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core.process import run, is_available

URL_RE = re.compile(r"^https?://[A-Za-z0-9][A-Za-z0-9._\-:]*", re.I)

BUILTIN_WORDLIST = [
    "admin", "login", "wp-admin", "wp-login.php", "robots.txt", "sitemap.xml",
    ".git/config", "backup", "phpinfo.php", "config.php", "index.php",
    "uploads", "api", "debug", "swagger", "vendor", ".htaccess", "cgi-bin",
    "shell", "flag.txt", ".env", "server-status", "readme.md", "test", "old",
]


@register_plugin
class DirBrute(PluginBase):
    name = "dir_brute"
    description = "Brute-force directories/files on an HTTP target (ffuf/gobuster or built-in)"
    category = "pentes"

    async def execute(self, target: str, wordlist: str = "", **kwargs) -> PluginResult:
        url = (target or "").strip().rstrip("/")
        if not URL_RE.match(url):
            return PluginResult(
                module="pentes", plugin="dir_brute", target=target,
                success=False, error=f"Invalid URL: '{target}'. Expected http(s)://host[:port]"
            )

        words = BUILTIN_WORDLIST
        if wordlist:
            sandbox = kwargs.get("sandbox")
            from ctf.core import workspace as ws_util
            path = ws_util.resolve_sandboxed(wordlist, sandbox) if sandbox else None
            if path is None or not path.exists():
                return PluginResult(
                    module="pentes", plugin="dir_brute", target=target,
                    success=False,
                    error=f"Wordlist not found inside the active workspace: '{wordlist}'."
                )
            words = [ln.strip() for ln in path.read_text(errors="replace").splitlines() if ln.strip()]

        if not words:
            return PluginResult(
                module="pentes", plugin="dir_brute", target=target,
                success=False, error="Wordlist is empty."
            )

        # Fast path with system fuzzer.
        tool = None
        if is_available("ffuf"):
            tool = "ffuf"
        elif is_available("gobuster"):
            tool = "gobuster"

        if tool == "ffuf":
            result = await run(
                "ffuf", "-u", f"{url}/FUZZ", "-w", "L:PAYLOAD", "-mc", "200,204,301,302,307,401,403",
                "-t", "8", "-timeout", "10", "-s", timeout=120,
            )
            if result.ok and result.stdout:
                hits = sorted({ln.strip().lstrip("/") for ln in result.stdout.splitlines() if ln.strip()})
                return PluginResult(
                    module="pentes", plugin="dir_brute", target=target,
                    success=True, data={"paths": hits, "base": url, "count": len(hits), "method": "ffuf"},
                    raw=result.stdout,
                )
        elif tool == "gobuster":
            result = await run(
                "gobuster", "dir", "-u", url, "-w", "/dev/stdin", "-q", "-t", "8",
                timeout=120,
            )
            if result.ok and result.stdout:
                hits = sorted({ln.strip() for ln in result.stdout.splitlines() if ln.strip()})
                return PluginResult(
                    module="pentes", plugin="dir_brute", target=target,
                    success=True, data={"paths": hits, "base": url, "count": len(hits), "method": "gobuster"},
                    raw=result.stdout,
                )

        # Pure Python concurrent GET scan.
        return await self._http_scan(url, words)

    async def _http_scan(self, base: str, words: list) -> PluginResult:
        found = []
        headers = {"User-Agent": "ctf-toolkit/0.1"}
        sem = asyncio.Semaphore(12)

        async def check(word):
            async with sem:
                path = word if word.startswith("/") else f"/{word}"
                try:
                    async with httpx.AsyncClient(
                        timeout=httpx.Timeout(8.0), headers=headers, follow_redirects=False
                    ) as client:
                        resp = await client.get(f"{base}{path}")
                        size = len(resp.content)
                        if resp.status_code in (200, 301, 302, 307, 401, 403):
                            found.append({
                                "path": path,
                                "status": resp.status_code,
                                "size": size,
                            })
                except (httpx.HTTPError, httpx.TimeoutException):
                    pass

        await asyncio.gather(*[check(w) for w in words])
        found.sort(key=lambda x: (x["status"], x["path"]))
        return PluginResult(
            module="pentes", plugin="dir_brute", target=base,
            success=True, data={"paths": found, "base": base, "count": len(found), "method": "http-scan"},
        )

    def parse(self, raw_output: str) -> dict:
        hits = [ln.strip() for ln in raw_output.splitlines() if ln.strip()]
        return {"paths": hits, "count": len(hits), "method": "raw"}
