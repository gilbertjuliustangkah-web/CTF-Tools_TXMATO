"""
Recon - DNS Lookup Plugin
Pure Python DNS record lookup.
"""
import asyncio
import socket
from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core.process import run, is_available


@register_plugin
class DnsLookup(PluginBase):
    name = "dns_lookup"
    description = "DNS record lookup: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR"
    category = "recon"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        record_type = kwargs.get("type", "A")
        domain = target.strip().lower()

        if is_available("dig"):
            return await self._dig_lookup(domain, record_type)

        return self._python_lookup(domain, record_type)

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    async def _dig_lookup(self, domain: str, record_type: str) -> PluginResult:
        result = await run("dig", "+short", domain, record_type, timeout=10)
        records = [line.strip() for line in result.stdout.splitlines() if line.strip()]

        # Also get ANY records
        any_result = await run("dig", "+short", domain, "ANY", timeout=10)

        return PluginResult(
            module="recon", plugin="dns_lookup", target=domain,
            success=True,
            data={
                "domain": domain,
                "query_type": record_type,
                "records": records,
                "any_records": [l.strip() for l in any_result.stdout.splitlines() if l.strip()],
                "method": "dig",
            }
        )

    def _python_lookup(self, domain: str, record_type: str) -> PluginResult:
        results = {}
        try:
            ips = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            results["A"] = list(set(addr[4][0] for addr in ips))
        except socket.gaierror as e:
            results["error"] = str(e)

        try:
            mx = socket.getaddrinfo(domain, 25, socket.AF_UNSPEC, socket.SOCK_STREAM)
            results["MX"] = list(set(addr[4][0] for addr in mx))
        except Exception:
            pass

        try:
            cname = socket.getfqdn(domain)
            results["FQDN"] = cname
        except Exception:
            pass

        return PluginResult(
            module="recon", plugin="dns_lookup", target=domain,
            success=bool(results),
            data={
                "domain": domain,
                "query_type": record_type,
                "records": results.get(record_type, results.get("A", [])),
                "all_results": results,
                "method": "python",
                "note": "Install dig for full record type support",
            }
        )
