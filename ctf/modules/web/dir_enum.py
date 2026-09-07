"""
Web - Directory Enumeration Plugin
Basic directory and file brute-force for web servers.
"""
import asyncio
from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core.process import run, is_available
from urllib.parse import urljoin


@register_plugin
class DirEnum(PluginBase):
    name = "dir_enum"
    description = "Web directory enumeration (wraps gobuster/dirsearch or built-in wordlist)"
    category = "web"

    COMMON_PATHS = [
        "/robots.txt", "/sitemap.xml", "/.git/", "/.env", "/wp-admin/",
        "/wp-login.php", "/administrator/", "/admin/", "/login", "/backup/",
        "/config.php", "/config.json", "/.htaccess", "/.htpasswd",
        "/phpinfo.php", "/info.php", "/test/", "/debug/", "/console/",
        "/.DS_Store", "/server-status", "/server-info", "/wp-config.php.bak",
        "/web.config", "/crossdomain.xml", "/.well-known/", "/api/",
        "/swagger/", "/docs/", "/graphql", "/health", "/status",
        "/wp-content/uploads/", "/wp-includes/", "/xmlrpc.php",
        "/readme.html", "/license.txt", "/CHANGELOG.md", "/backup.sql",
        "/dump.sql", "/db/", "/database/", "/data/", "/old/",
        "/new/", "/temp/", "/tmp/", "/cache/", "/log/", "/logs/",
    ]

    async def execute(self, target: str, **kwargs) -> PluginResult:
        url = target.rstrip("/")
        wordlist = kwargs.get("wordlist", "common")
        threads = kwargs.get("threads", 5)

        if is_available("gobuster"):
            return await self._gobuster(url, kwargs)
        elif is_available("dirsearch"):
            return await self._dirsearch(url, kwargs)

        return await self._builtin_scan(url)

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    async def _builtin_scan(self, url: str) -> PluginResult:
        import httpx

        found = []
        async with httpx.AsyncClient(timeout=5, follow_redirects=False, verify=False) as client:
            for path in self.COMMON_PATHS:
                full_url = urljoin(url + "/", path.lstrip("/"))
                try:
                    resp = await client.get(full_url)
                    if resp.status_code not in (404, 405, 500, 502, 503):
                        found.append({
                            "path": path,
                            "status": resp.status_code,
                            "size": len(resp.content),
                            "url": full_url,
                        })
                except Exception:
                    continue

        return PluginResult(
            module="web", plugin="dir_enum", target=url,
            success=True,
            data={
                "url": url,
                "found": found,
                "total_checked": len(self.COMMON_PATHS),
                "total_found": len(found),
                "method": "builtin",
            }
        )

    async def _gobuster(self, url: str, kwargs: dict) -> PluginResult:
        result = await run(
            "gobuster", "dir", "-u", url, "-w", "/usr/share/wordlists/dirb/common.txt",
            "-q", "--no-error", "--threads", str(kwargs.get("threads", 5)),
            timeout=120
        )
        entries = []
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                entries.append({"path": parts[0], "status": parts[1] if len(parts) > 1 else ""})
        return PluginResult(
            module="web", plugin="dir_enum", target=url,
            success=True,
            data={"url": url, "found": entries, "total_found": len(entries), "method": "gobuster"}
        )

    async def _dirsearch(self, url: str, kwargs: dict) -> PluginResult:
        result = await run(
            "dirsearch", "-u", url, "-q", "--format=json", timeout=120
        )
        return PluginResult(
            module="web", plugin="dir_enum", target=url,
            success=True,
            data={"url": url, "raw": result.stdout, "method": "dirsearch"}
        )
