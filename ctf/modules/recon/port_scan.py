"""
Recon - Port Scanner Plugin
Uses nmap if available, falls back to pure-Python socket scan.
"""
import asyncio
import re
import socket
from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core.process import run, is_available

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                443, 445, 993, 995, 1433, 1521, 3306, 3389,
                5432, 5900, 6379, 8080, 8443, 8888, 27017]

PORT_SPEC_RE = re.compile(r"^[0-9,\-\s]+$")
IP_OR_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-\:]*$")


@register_plugin
class PortScanner(PluginBase):
    name = "port_scan"
    description = "Scan open ports on a target (nmap or socket fallback)"
    category = "recon"

    async def execute(self, target: str, ports: str = "common", **kwargs) -> PluginResult:
        # Reject anything that could be interpreted as a CLI option/flag.
        if target.startswith("-"):
            return PluginResult(
                module="recon", plugin="port_scan", target=target,
                success=False, error=f"Invalid target: '{target}' must not start with '-'"
            )
        if not IP_OR_HOST_RE.match(target):
            return PluginResult(
                module="recon", plugin="port_scan", target=target,
                success=False, error=f"Invalid target: '{target}' contains illegal characters"
            )

        if is_available("nmap"):
            return await self._nmap_scan(target, ports)
        return await self._socket_scan(target, ports)

    async def _nmap_scan(self, target: str, ports: str) -> PluginResult:
        if ports == "common":
            port_arg = ["-F"]
        elif ports == "all":
            port_arg = ["-p-"]
        else:
            if not PORT_SPEC_RE.match(ports or ""):
                return PluginResult(
                    module="recon", plugin="port_scan", target=target,
                    success=False,
                    error=f"Invalid port spec: '{ports}'. Use 'common', 'all', or a list like 80,443,8080"
                )
            port_arg = ["-p", ports.strip()]
        # "--" terminates option parsing so a target can never be read as a flag.
        result = await run("nmap", "-sV", "--open", *port_arg, "--", target, timeout=120)
        if not result.ok and not result.stdout:
            return PluginResult(
                module="recon", plugin="port_scan", target=target,
                success=False, error=result.stderr
            )
        data = self.parse(result.stdout)
        return PluginResult(
            module="recon", plugin="port_scan", target=target,
            success=True, data=data, raw=result.stdout
        )

    async def _socket_scan(self, target: str, ports: str = "common") -> PluginResult:
        """Pure Python socket scan as nmap fallback."""
        if ports == "all":
            port_list = list(range(1, 65536))
        elif ports == "common":
            port_list = COMMON_PORTS
        else:
            if not PORT_SPEC_RE.match(ports or ""):
                return PluginResult(
                    module="recon", plugin="port_scan", target=target,
                    success=False,
                    error=f"Invalid port spec: '{ports}'. Use 'common', 'all', or a list like 80,443,8080"
                )
            port_list = []
            for chunk in ports.replace(" ", "").split(","):
                if "-" in chunk:
                    lo, hi = chunk.split("-")
                    port_list.extend(range(int(lo), int(hi) + 1))
                elif chunk:
                    port_list.append(int(chunk))
            port_list = [p for p in port_list if 1 <= p <= 65535]

        open_ports = []

        async def check(port: int):
            try:
                conn = asyncio.open_connection(target, port)
                _, writer = await asyncio.wait_for(conn, timeout=1)
                writer.close()
                await writer.wait_closed()
                service = self._guess_service(port)
                open_ports.append({"port": port, "state": "open", "service": service, "version": ""})
            except Exception:
                pass

        await asyncio.gather(*[check(p) for p in port_list])
        open_ports.sort(key=lambda x: x["port"])

        return PluginResult(
            module="recon", plugin="port_scan", target=target,
            success=True,
            data={"ports": open_ports, "method": "socket"},
        )

    def parse(self, raw_output: str) -> dict:
        ports = []
        for line in raw_output.splitlines():
            m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
            if m:
                ports.append({
                    "port": int(m.group(1)),
                    "protocol": m.group(2),
                    "state": "open",
                    "service": m.group(3),
                    "version": m.group(4).strip(),
                })
        return {"ports": ports, "method": "nmap"}

    def _guess_service(self, port: int) -> str:
        known = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 135: "msrpc", 139: "netbios",
            143: "imap", 443: "https", 445: "smb", 993: "imaps",
            995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql",
            3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
            8080: "http-alt", 8443: "https-alt", 8888: "jupyter", 27017: "mongodb",
        }
        return known.get(port, "unknown")
