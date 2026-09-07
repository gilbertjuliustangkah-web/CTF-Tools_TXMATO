"""
Web - HTTP recon plugins
HTTP headers grabber and robots.txt parser.
"""
from urllib.parse import urlparse

import httpx

from ctf.core.plugin import PluginBase, PluginResult, register_plugin

TIMEOUT = 12.0


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ValueError("Empty URL")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parts = urlparse(url)
    if not parts.hostname:
        raise ValueError("URL has no host")
    return url


async def _fetch(url: str, timeout: float = TIMEOUT):
    """GET a URL with redirects. Returns (final_url, response)."""
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
        resp = await client.get(url)
        return resp


@register_plugin
class HttpHeaders(PluginBase):
    name = "http_headers"
    description = "Fetch HTTP headers, status, and redirect chain of a URL"
    category = "web"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        try:
            url = _normalize_url(target)
        except ValueError as exc:
            return PluginResult(module="web", plugin="http_headers", target=target,
                                success=False, error=str(exc))
        try:
            resp = await _fetch(url)
        except httpx.HTTPError as exc:
            return PluginResult(module="web", plugin="http_headers", target=target,
                                success=False, error=f"Request failed: {exc}")

        cookies = [ck.name for ck in resp.cookies.jar]
        data = {
            "url": str(resp.url),
            "status": resp.status_code,
            "redirections": len(resp.history),
            "headers": [[k, v] for k, v in resp.headers.items()],
            "content_type": resp.headers.get("content-type", ""),
            "server": resp.headers.get("server", ""),
            "cookies": cookies,
            "body_size": len(resp.content),
        }
        return PluginResult(module="web", plugin="http_headers", target=target,
                            success=True, data=data)

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}


@register_plugin
class RobotsTxt(PluginBase):
    name = "robots_txt"
    description = "Fetch and parse robots.txt (disallowed paths, sitemap)"
    category = "web"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        try:
            base = _normalize_url(target)
        except ValueError as exc:
            return PluginResult(module="web", plugin="robots_txt", target=target,
                                success=False, error=str(exc))

        robots_url = base.rstrip("/") + "/robots.txt"
        try:
            resp = await _fetch(robots_url)
        except httpx.HTTPError as exc:
            return PluginResult(module="web", plugin="robots_txt", target=target,
                                success=False, error=f"Request failed: {exc}")

        if resp.status_code == 404:
            return PluginResult(module="web", plugin="robots_txt", target=target,
                                success=False, error=f"No robots.txt (404) at {robots_url}")

        text = resp.text
        entries = []      # (user_agent, [rules])
        sitemaps = []
        current_agent = "*"
        current_rules = []
        allow_rules = []
        disallow_rules = []

        def flush():
            nonlocal current_agent, current_rules, allow_rules, disallow_rules
            if current_rules or allow_rules or disallow_rules:
                entries.append((current_agent, allow_rules, disallow_rules, current_rules))
            current_agent = "*"
            current_rules, allow_rules, disallow_rules = [], [], []

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            low = line.lower()
            if low.startswith("user-agent:"):
                if current_rules or allow_rules or disallow_rules:
                    flush()
                current_agent = line.split(":", 1)[1].strip()
            elif low.startswith("allow:"):
                allow_rules.append(line.split(":", 1)[1].strip())
            elif low.startswith("disallow:"):
                disallow_rules.append(line.split(":", 1)[1].strip())
            elif low.startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())
            elif low.startswith(("crawl-delay:", "host:", "request-rate:")):
                current_rules.append(line)
        flush()

        data = {
            "url": robots_url,
            "status": resp.status_code,
            "entries": [[agent, allows, disallows, other]
                        for agent, allows, disallows, other in entries],
            "sitemaps": sitemaps,
            "interesting_paths": sorted({
                p
                for _, _, dis, _ in entries
                for p in dis
                if p.startswith("/") and p != "/"
            }),
        }
        return PluginResult(module="web", plugin="robots_txt", target=target,
                            success=True, data=data)

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}