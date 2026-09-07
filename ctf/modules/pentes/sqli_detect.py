"""
Pentest - SQL Injection Detection Plugin

Sends a small set of benign GET probes against a target URL and looks for
database error signatures or anomalous responses (e.g. 200→500 on a quote).
Read-only, rate-limited, and intended for use ONLY against systems you are
authorized to test (local CTF labs, HTB/THM boxes).
"""
import asyncio
import re

import httpx

from ctf.core.plugin import PluginBase, PluginResult, register_plugin

URL_RE = re.compile(r"^https?://[A-Za-z0-9][A-Za-z0-9._\-:]*", re.I)
PROBE_DELAY = 0.2   # seconds between probes (rate limit)

# Benign single-statement payloads; nothing destructive, no stacked queries.
PROBES = [
    ("bool_true", "' OR '1'='1' -- "),
    ("quote", "'"),
    ("double_quote", '"'),
    ("comment_end", "' -- "),
    ("union_null", "' UNION SELECT NULL-- "),
    ("paren", "') OR ('1'='1"),
]

DB_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql", re.I),
    re.compile(r"sql syntax|near \"|near '", re.I),
    re.compile(r"mysql|mariadb|sqlite|sqlite3\.error|integrityerror", re.I),
    re.compile(r"postgresql|psycopg|sqlstate|pg_query", re.I),
    re.compile(r"ora-\d{4,5}|oracle", re.I),
    re.compile(r"microsoft ole db|odbc|sql server|sqlserver", re.I),
    re.compile(r"unterminated quoted string|syntax error at or near", re.I),
    re.compile(r"query failed|database error|db error|invalid query", re.I),
]


@register_plugin
class SqliDetect(PluginBase):
    name = "sqli_detect"
    description = "Detect SQL injection in GET parameters (error/differential based)"
    category = "pentes"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        url = (target or "").strip().rstrip("/")
        if not URL_RE.match(url):
            return PluginResult(
                module="pentes", plugin="sqli_detect", target=target,
                success=False,
                error=f"Invalid URL: '{target}'. Expected http(s)://host[:port]/path?param=value"
            )
        if "?" not in url:
            return PluginResult(
                module="pentes", plugin="sqli_detect", target=target,
                success=False,
                error="Provide a URL with a query parameter, e.g. http://target/product?id=1"
            )

        findings = []
        baseline = self._capture(url)

        for name, payload in PROBES:
            probe_url = self._inject(url, payload)
            probe = self._capture(probe_url)
            finding = self._analyze(name, payload, baseline, probe)
            if finding:
                findings.append(finding)
            await asyncio.sleep(PROBE_DELAY)

        return PluginResult(
            module="pentes", plugin="sqli_detect", target=url,
            success=True,
            data={
                "url": url,
                "baseline_status": baseline["status"],
                "probes_sent": len(PROBES),
                "findings": findings,
                "count": len(findings),
            },
        )

    def _capture(self, url: str) -> dict:
        """Return status + body snippet for a URL (never follows redirects off-host)."""
        try:
            resp = httpx.Client(timeout=httpx.Timeout(8.0), follow_redirects=False).get(url)
            return {"status": resp.status_code, "body": resp.text[:4000]}
        except (httpx.HTTPError, httpx.TimeoutException):
            return {"status": 0, "body": ""}

    def _inject(self, url: str, payload: str) -> str:
        """Replace the value of the last query parameter with the payload."""
        if "=" in url:
            head, _, _ = url.rpartition("=")
            return f"{head}={payload}"
        return f"{url}&q={payload}"

    def _analyze(self, name: str, payload: str, base: dict, probe: dict) -> dict | None:
        body = probe["body"]
        reasons = []

        for pat in DB_ERROR_PATTERNS:
            if pat.search(body):
                reasons.append(f"DB error signature: {pat.pattern[:60]}")
                break

        if probe["status"] == 500 and base["status"] != 500:
            reasons.append("server error (500) on probe vs baseline")

        if probe["status"] == 0:
            reasons.append("connection dropped/failed on probe")

        if not reasons:
            return None

        return {
            "probe": name,
            "payload": payload.strip(),
            "status": probe["status"],
            "baseline_status": base["status"],
            "reasons": reasons[:3],
            "severity": "high" if probe["status"] == 500 or "error signature" in reasons[0] else "medium",
        }

    def parse(self, raw_output: str) -> dict:
        return {"findings": [], "count": 0}