"""
Pentest - Reflected XSS Detection Plugin

Sends a benign marker payload in GET parameters and checks whether it is
reflected back unencoded in the response body (reflected XSS indicator) and
whether hardening headers (CSP, X-Content-Type-Options, X-Frame-Options) are
absent. Read-only, rate-limited; authorized targets / CTF labs only.
"""
import asyncio
import re

import httpx

from ctf.core.plugin import PluginBase, PluginResult, register_plugin

URL_RE = re.compile(r"^https?://[A-Za-z0-9][A-Za-z0-9._\-:]*", re.I)
PROBE_DELAY = 0.2

MARKER = "ctfxss7a3f"
# Payload is inert (no executable JS); only proves reflection + escaping state.
PAYLOADS = [
    ("plain", MARKER),
    ("angle", f"<{MARKER}>"),
    ("tag_break", f'"><{MARKER}>'),
]

HARDENING_HEADERS = {
    "content-security-policy": "CSP",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
}


@register_plugin
class XssDetect(PluginBase):
    name = "xss_detect"
    description = "Detect reflected XSS indicators + missing hardening headers"
    category = "pentes"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        url = (target or "").strip().rstrip("/")
        if not URL_RE.match(url):
            return PluginResult(
                module="pentes", plugin="xss_detect", target=target,
                success=False,
                error=f"Invalid URL: '{target}'. Expected http(s)://host[:port]/path?param=value"
            )
        if "?" not in url:
            return PluginResult(
                module="pentes", plugin="xss_detect", target=target,
                success=False,
                error="Provide a URL with a query parameter, e.g. http://target/search?q=test"
            )

        findings = []
        headers = {}

        for name, payload in PAYLOADS:
            probe_url = self._inject(url, payload)
            resp, body = self._capture(probe_url)
            if resp is None:
                findings.append({
                    "probe": name, "reflected": False, "status": 0,
                    "note": "request failed/connection error",
                })
                await asyncio.sleep(PROBE_DELAY)
                continue
            headers = dict(resp.headers)

            reflected = MARKER in body
            # True XSS hint only when marker survives inside < > without escaping.
            literal = f"<{MARKER}>" in body or f'">{MARKER}>' in body
            findings.append({
                "probe": name,
                "status": resp.status_code,
                "reflected": reflected,
                "unencoded_tag": literal,
                "note": "marker reflected unencoded (XSS-prone)" if literal else
                        ("marker reflected" if reflected else "no reflection"),
            })
            await asyncio.sleep(PROBE_DELAY)

        missing = [HARDENING_HEADERS[h] for h in HARDENING_HEADERS if h not in headers]
        nu = "X-XSS-Protection"
        vulnerabilities = [
            f for f in findings if f.get("unencoded_tag")
        ]

        return PluginResult(
            module="pentes", plugin="xss_detect", target=url,
            success=True,
            data={
                "url": url,
                "findings": findings,
                "count": len(findings),
                "probes_sent": len(PAYLOADS),
                "hardening_missing": missing,
                "x_xss_protection": nu in headers,
                "reflected_xss_likely": len(vulnerabilities) > 0,
            },
        )

    def _capture(self, url: str):
        """Return (response, body_text) for a URL; (None, "") on failure."""
        try:
            resp = httpx.Client(timeout=httpx.Timeout(8.0), follow_redirects=False).get(url)
            return resp, resp.text[:4000]
        except (httpx.HTTPError, httpx.TimeoutException):
            return None, ""

    def _inject(self, url: str, payload: str) -> str:
        """Replace the value of the last query parameter with the marker payload."""
        if "=" in url:
            head, _, _ = url.rpartition("=")
            return f"{head}={payload}"
        return f"{url}&q={payload}"

    def parse(self, raw_output: str) -> dict:
        return {"findings": [], "count": 0}