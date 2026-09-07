"""
Forensic - Volatility Memory Analysis Plugin
Wraps volatility3 for memory dump analysis.
"""
from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core.process import run, is_available


@register_plugin
class VolatilityAnalyze(PluginBase):
    name = "volatility_analyze"
    description = "Memory forensics with Volatility 3: processes, network, registry, etc."
    category = "forensic"

    AVAILABLE_PLUGINS = [
        "windows.pslist", "windows.pstree", "windows.netstat",
        "windows.cmdline", "windows.dlllist", "windows.handles",
        "windows.registry.hivelist", "windows.registry.printkey",
        "windows.filescan", "windows.malfind",
        "linux.pslist", "linux.bash", "linux.check_syscall",
        "mac.pslist",
    ]

    async def execute(self, target: str, **kwargs) -> PluginResult:
        if not is_available("vol"):
            return PluginResult(
                module="forensic", plugin="volatility_analyze", target=target,
                success=False,
                error="volatility3 not found. Install: pip install volatility3"
            )

        plugin_name = kwargs.get("plugin", "windows.pslist")
        if plugin_name not in self.AVAILABLE_PLUGINS:
            plugin_name = "windows.pslist"

        result = await run(
            "vol", "-f", target, plugin_name,
            timeout=300
        )

        data = {
            "plugin_used": plugin_name,
            "raw_output": result.stdout,
            "available_plugins": self.AVAILABLE_PLUGINS,
        }

        if plugin_name == "windows.pslist" and result.ok:
            data["processes"] = self._parse_pslist(result.stdout)

        return PluginResult(
            module="forensic", plugin="volatility_analyze", target=target,
            success=result.ok,
            data=data,
            error="" if result.ok else result.stderr
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _parse_pslist(self, output: str) -> list[dict]:
        processes = []
        lines = output.strip().split("\n")
        if len(lines) < 2:
            return processes

        for line in lines[2:]:
            parts = line.split()
            if len(parts) >= 6:
                processes.append({
                    "pid": parts[1] if len(parts) > 1 else "",
                    "ppid": parts[2] if len(parts) > 2 else "",
                    "imageFileName": parts[3] if len(parts) > 3 else "",
                    "offset": parts[0] if parts else "",
                })
        return processes
