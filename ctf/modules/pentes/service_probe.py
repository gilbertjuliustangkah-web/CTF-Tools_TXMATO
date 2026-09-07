"""
Pentest - Service Probing Plugin

Version/software fingerprinting of open ports. Uses nmap -sV when available,
otherwise a fast pure-Python banner grab / heuristic guess. Input validation
mirrors the recon port scanner to keep everything argv-safe.
"""
import asyncio
import re

from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core.process import run, is_available

TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-\:]*$")
PORTS_RE = re.compile(r"^[0-9,\-\s]+$")

SERVICE_GUESS = {
    "ssh": 22, "smtp": 25, "http": 80, "https": 443, "smb": 445,
    "mssql": 1433, "mysql": 3306, "rdp": 3389, "postgresql": 5432,
    "redis": 6379, "mongodb": 27017,
}
BANNER_PATTERNS = [
    (re.compile(rb"SSH-\d+\.\d+", re.I), "ssh"),
    (re.compile(rb"220 .*SMTP|ESMTP", re.I), "smtp"),
    (re.compile(rb"HTTP/\d\.\d \d{3}"), "http"),
    (re.compile(rb"220 .*FTP", re.I), "ftp"),
    (re.compile(rb"^\+OK POP3", re.I), "pop3"),
    (re.compile(rb"^\* OK .* IMAP", re.I), "imap"),
    (re.compile(rb"Redis|redis_version", re.I), "redis"),
    (re.compile(rb"MySQL|ERROR \[", re.I), "mysql"),
]


@register_plugin
class ServiceProbe(PluginBase):
    name = "service_probe"
    description = "Probe open ports for service/version info (nmap -sV or banner grab)"
    category = "pentes"

    async def execute(self, target: str, ports: str = "common", **kwargs) -> PluginResult:
        target = (target or "").strip()
        if target.startswith("-") or not TARGET_RE.match(target):
            return PluginResult(
                module="pentes", plugin="service_probe", target=target,
                success=False, error=f"Invalid target: '{target}'"
            )

        if is_available("nmap"):
            return await self._nmap(target, ports)
        return await self._banner_grab(target, ports)

    async def _nmap(self, target: str, ports: str) -> PluginResult:
        if ports == "common":
            port_arg = ["-F"]
        elif ports == "all":
            port_arg = ["-p-"]
        else:
            if not PORTS_RE.match(ports or ""):
                return PluginResult(
                    module="pentes", plugin="service_probe", target=target,
                    success=False, error=f"Invalid port spec: '{ports}'"
                )
            port_arg = ["-p", ports.strip()]
        result = await run("nmap", "-sV", "--open", *port_arg, "--", target, timeout=180)
        if not result.ok and not result.stdout:
            return PluginResult(
                module="pentes", plugin="service_probe", target=target,
                success=False, error=result.stderr
            )
        data = self.parse(result.stdout)
        data["method"] = "nmap"
        return PluginResult(
            module="pentes", plugin="service_probe", target=target,
            success=True, data=data, raw=result.stdout
        )

    async def _banner_grab(self, target: str, ports: str) -> PluginResult:
        port_list = self._resolve_ports(ports)
        if port_list is None:
            return PluginResult(
                module="pentes", plugin="service_probe", target=target,
                success=False, error=f"Invalid port spec: '{ports}'"
            )

        found = []

        async def probe(port: int):
            guess = self._guess_service(port)
            banner = ""
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port), timeout=2
                )
                try:
                    banner_data = await asyncio.wait_for(reader.read(2048), timeout=2)
                    banner = banner_data.decode(errors="replace").strip()
                except Exception:
                    banner = ""
                writer.close()
                await writer.wait_closed()
            except Exception:
                return

            service = self._detect_service(banner, guess)
            found.append({
                "port": port,
                "state": "open",
                "service": service,
                "version": self._extract_version(banner, service),
                "banner": banner[:200],
            })

        await asyncio.gather(*[probe(p) for p in port_list])
        found.sort(key=lambda x: x["port"])
        return PluginResult(
            module="pentes", plugin="service_probe", target=target,
            success=True, data={"ports": found, "method": "banner-grab"},
        )

    def _resolve_ports(self, ports: str):
        if ports == "all":
            return list(range(1, 65536))
        if ports == "common":
            return sorted(SERVICE_GUESS.values())
        if not PORTS_RE.match(ports or ""):
            return None
        out = []
        for chunk in ports.replace(" ", "").split(","):
            if "-" in chunk:
                lo, hi = chunk.split("-")
                out.extend(range(int(lo), int(hi) + 1))
            elif chunk:
                out.append(int(chunk))
        return [p for p in out if 1 <= p <= 65535]

    def _guess_service(self, port: int) -> str:
        for svc, p in SERVICE_GUESS.items():
            if p == port:
                return svc
        return "unknown"

    def _detect_service(self, banner: str, guess: str) -> str:
        raw = banner.encode(errors="replace")
        if raw:
            for pat, svc in BANNER_PATTERNS:
                if pat.search(raw):
                    return svc
        return guess

    def _extract_version(self, banner: str, service: str) -> str:
        if service == "ssh":
            m = re.search(r"SSH-\d+\.\d+", banner)
            return m.group(0) if m else ""
        if service in ("http", "https"):
            m = re.search(r"Server:\s*(.+)", banner)
            return m.group(1).strip() if m else ""
        if service in ("smtp", "ftp"):
            return banner[:80]
        return ""

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
        return {"ports": ports}
