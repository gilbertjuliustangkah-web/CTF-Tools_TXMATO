"""
Recon - WHOIS Lookup Plugin
WHOIS domain registration lookup.
"""
from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core.process import run, is_available


@register_plugin
class WhoisLookup(PluginBase):
    name = "whois_lookup"
    description = "WHOIS domain registration lookup (registrar, dates, name servers)"
    category = "recon"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        domain = target.strip().lower()

        if not is_available("whois"):
            return PluginResult(
                module="recon", plugin="whois_lookup", target=domain,
                success=False,
                error="whois not found. Install: apt install whois / scoop install whois"
            )

        result = await run("whois", domain, timeout=30)

        if not result.ok and not result.stdout:
            return PluginResult(
                module="recon", plugin="whois_lookup", target=domain,
                success=False, error=result.stderr or "WHOIS lookup failed"
            )

        info = self._parse_whois(result.stdout)
        return PluginResult(
            module="recon", plugin="whois_lookup", target=domain,
            success=True, data=info
        )

    def parse(self, raw_output: str) -> dict:
        return self._parse_whois(raw_output)

    def _parse_whois(self, output: str) -> dict:
        info = {"raw": output, "fields": {}}

        field_map = {
            "Registrar": "registrar",
            "Creation Date": "creation_date",
            "Updated Date": "updated_date",
            "Registry Expiry Date": "expiry_date",
            "Expiry Date": "expiry_date",
            "Name Server": "name_servers",
            "Nameservers": "name_servers",
            "Domain Status": "status",
            "Registrant Organization": "registrant_org",
            "Registrant Country": "registrant_country",
            "DNSSEC": "dnssec",
        }

        name_servers = []
        for line in output.splitlines():
            for display_name, key in field_map.items():
                if line.strip().lower().startswith(display_name.lower()):
                    _, _, value = line.partition(":")
                    value = value.strip()
                    if key == "name_servers":
                        if value.lower() not in [ns.lower() for ns in name_servers]:
                            name_servers.append(value)
                    else:
                        info["fields"][key] = value

        if name_servers:
            info["fields"]["name_servers"] = name_servers

        return info
