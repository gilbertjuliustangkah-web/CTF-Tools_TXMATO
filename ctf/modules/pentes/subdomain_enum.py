"""
Pentest - Subdomain Enumeration Plugin

Pure-Python DNS subdomain brute-forcing against the target domain, with an
optional fast pass via sublist3r when available. Reuses a wordlist from the
active workspace if provided, otherwise a small built-in wordlist. Input is
validated so it can never be treated as a CLI flag or injected into a shell.
"""
import asyncio
import re
from pathlib import Path

from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core.process import run, is_available
from ctf.core import workspace as ws_util

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")

BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "webmail", "admin", "portal", "vpn", "remote",
    "api", "dev", "staging", "test", "beta", "shop", "store", "blog",
    "ns1", "ns2", "mx", "smtp", "pop", "imap", "dns", "dns1", "dns2",
    "git", "jenkins", "grafana", "gitlab", "jira", "confluence", "kibana",
    "monitor", "metrics", "prometheus", "crm", "erp", "intranet", "owa",
    "autodiscover", "exchange", "rdp", "ssh", "web", "backup", "old",
]


@register_plugin
class SubdomainEnum(PluginBase):
    name = "subdomain_enum"
    description = "Enumerate subdomains of a target domain (DNS brute force)"
    category = "pentes"

    async def execute(self, target: str, wordlist: str = "", **kwargs) -> PluginResult:
        domain = (target or "").strip().lower()
        if not DOMAIN_RE.match(domain):
            return PluginResult(
                module="pentes", plugin="subdomain_enum", target=target,
                success=False,
                error=f"Invalid domain: '{target}'. Expected a hostname like example.com"
            )

        words = BUILTIN_WORDLIST
        if wordlist:
            sandbox = kwargs.get("sandbox")
            path = None
            if sandbox:
                path = ws_util.resolve_sandboxed(wordlist, sandbox)
            if path is None or not path.exists():
                return PluginResult(
                    module="pentes", plugin="subdomain_enum", target=target,
                    success=False,
                    error=f"Wordlist not found inside the active workspace: '{wordlist}'. Upload it to the workspace first."
                )
            words = [ln.strip().lower() for ln in path.read_text(errors="replace").splitlines() if ln.strip()]

        if not words:
            return PluginResult(
                module="pentes", plugin="subdomain_enum", target=target,
                success=False, error="Wordlist is empty."
            )

        # Fast path: sublist3r (OSINT aggregation) if available.
        if is_available("sublist3r"):
            result = await run("sublist3r", "-d", domain, "--silent", timeout=120)
            if result.ok and result.stdout:
                found = sorted({s.strip().lower() for s in result.stdout.splitlines() if s.strip()})
                return PluginResult(
                    module="pentes", plugin="subdomain_enum", target=target,
                    success=True,
                    data={"subdomains": found, "domain": domain,
                          "count": len(found), "method": "sublist3r"},
                    raw=result.stdout,
                )

        # Pure Python DNS brute force (concurrent).
        found = []

        async def check(sub):
            host = f"{sub}.{domain}"
            try:
                infos = await asyncio.get_event_loop().getaddrinfo(host, None, proto=0, type=0)
                ips = sorted({info[4][0] for info in infos})
                if ips:
                    found.append({"host": host, "ips": ips})
            except Exception:
                pass

        batch = 24
        for i in range(0, len(words), batch):
            await asyncio.gather(*[check(w) for w in words[i:i + batch]])
        found.sort(key=lambda x: x["host"])

        return PluginResult(
            module="pentes", plugin="subdomain_enum", target=target,
            success=True,
            data={"subdomains": found, "domain": domain,
                  "count": len(found), "method": "dns-brute"},
        )

    def parse(self, raw_output: str) -> dict:
        lines = [ln.strip() for ln in raw_output.splitlines() if ln.strip()]
        return {"subdomains": lines, "count": len(lines), "method": "raw"}
