"""
Recon - SSL/TLS Certificate Check Plugin
Analyze SSL/TLS certificates for a domain.
"""
import ssl
import socket
from datetime import datetime
from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core.process import run, is_available


@register_plugin
class SslCheck(PluginBase):
    name = "ssl_check"
    description = "SSL/TLS certificate analysis: issuer, expiry, SAN, protocol versions"
    category = "recon"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        host = target.strip()
        port = kwargs.get("port", 443)
        if ":" in host:
            host, _, port_str = host.partition(":")
            port = int(port_str)

        try:
            cert_info = self._get_cert(host, port)
        except Exception as e:
            return PluginResult(
                module="recon", plugin="ssl_check", target=target,
                success=False, error=f"Failed to connect: {e}"
            )

        warnings = self._check_weakness(cert_info)

        return PluginResult(
            module="recon", plugin="ssl_check", target=target,
            success=True, data=cert_info | {"warnings": warnings}
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _get_cert(self, host: str, port: int) -> dict:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(10)
            s.connect((host, port))
            cert = s.getpeercert()

        info = {
            "host": host,
            "port": port,
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "serial": cert.get("serialNumber", ""),
            "not_before": cert.get("notBefore", ""),
            "not_after": cert.get("notAfter", ""),
            "san": [],
            "version": cert.get("version", ""),
            "ocsp": cert.get("OCSP", []),
        }

        san_entries = cert.get("subjectAltName", [])
        info["san"] = [entry[1] for entry in san_entries]

        try:
            not_after = datetime.strptime(info["not_after"], "%b %d %H:%M:%S %Y %Z")
            days_left = (not_after - datetime.utcnow()).days
            info["days_until_expiry"] = days_left
            info["is_expired"] = days_left < 0
        except Exception:
            info["days_until_expiry"] = None
            info["is_expired"] = None

        return info

    def _check_weakness(self, info: dict) -> list[str]:
        warnings = []
        if info.get("is_expired"):
            warnings.append("Certificate is EXPIRED")
        elif info.get("days_until_expiry") is not None and info["days_until_expiry"] < 30:
            warnings.append(f"Certificate expires in {info['days_until_expiry']} days")

        issuer = info.get("issuer", {}).get("organizationName", "")
        if "Let's Encrypt" in issuer:
            warnings.append("Let's Encrypt certificate (free, commonly used in CTFs)")

        return warnings
