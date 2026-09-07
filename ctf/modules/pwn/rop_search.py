"""
Pwn - ROP Gadget Search Plugin
Search for ROP gadgets using ropper or ROPgadget.
"""
import re
from ctf.core.plugin import PluginBase, PluginResult, register_plugin
from ctf.core.process import run, is_available


@register_plugin
class RopSearch(PluginBase):
    name = "rop_search"
    description = "Search for ROP gadgets in binaries (wraps ropper/ROPgadget)"
    category = "pwn"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        max_gadgets = kwargs.get("max_gadgets", 50)
        search_term = kwargs.get("search", "")

        if is_available("ropper"):
            return await self._ropper_search(target, max_gadgets, search_term)
        elif is_available("ROPgadget"):
            return await self._ropgadget_search(target, max_gadgets, search_term)

        return PluginResult(
            module="pwn", plugin="rop_search", target=target,
            success=False,
            error="No ROP tool found. Install: pip install ropper or apt install ropgadget"
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    async def _ropper_search(self, target: str, max_gadgets: int, search: str) -> PluginResult:
        args = ["ropper", "--file", target]
        if search:
            args.extend(["--search", search])
        else:
            args.extend(["--search", "pop", "--nocolor"])

        result = await run(*args, timeout=60)

        gadgets = self._parse_ropper(result.stdout)

        useful = self._categorize_gadgets(gadgets)

        return PluginResult(
            module="pwn", plugin="rop_search", target=target,
            success=True,
            data={
                "target": target,
                "gadgets": gadgets[:max_gadgets],
                "total_found": len(gadgets),
                "useful": useful,
                "method": "ropper",
            }
        )

    async def _ropgadget_search(self, target: str, max_gadgets: int, search: str) -> PluginResult:
        args = ["ROPgadget", "--binary", target]
        if search:
            args.extend(["--only", f"{search}|pop"])

        result = await run(*args, timeout=60)

        gadgets = []
        for line in result.stdout.splitlines():
            m = re.match(r"(0x[0-9a-fA-F]+) : (.+)", line.strip())
            if m:
                gadgets.append({"address": m.group(1), "gadget": m.group(2)})

        useful = self._categorize_gadgets(gadgets)

        return PluginResult(
            module="pwn", plugin="rop_search", target=target,
            success=True,
            data={
                "target": target,
                "gadgets": gadgets[:max_gadgets],
                "total_found": len(gadgets),
                "useful": useful,
                "method": "ROPgadget",
            }
        )

    def _parse_ropper(self, output: str) -> list[dict]:
        gadgets = []
        for line in output.splitlines():
            m = re.match(r"(0x[0-9a-fA-F]+):\s*(.+)", line.strip())
            if m:
                gadgets.append({"address": m.group(1), "gadget": m.group(2).strip()})
        return gadgets

    def _categorize_gadgets(self, gadgets: list[dict]) -> dict:
        useful = {
            "pop_rdi": [], "pop_rsi": [], "pop_rdx": [], "pop_rax": [],
            "syscall": [], "ret": [], "int_80": [],
            "mov_esp": [], "jmp_rsp": [],
        }
        for g in gadgets:
            gadget_text = g.get("gadget", "")
            if "pop rdi" in gadget_text or "pop edi" in gadget_text:
                useful["pop_rdi"].append(g)
            if "pop rsi" in gadget_text or "pop esi" in gadget_text:
                useful["pop_rsi"].append(g)
            if "pop rdx" in gadget_text or "pop edx" in gadget_text:
                useful["pop_rdx"].append(g)
            if "pop rax" in gadget_text or "pop eax" in gadget_text:
                useful["pop_rax"].append(g)
            if "syscall" in gadget_text:
                useful["syscall"].append(g)
            if gadget_text.strip() == "ret" or gadget_text.strip() == "ret;":
                useful["ret"].append(g)
            if "int 0x80" in gadget_text or "int 80" in gadget_text:
                useful["int_80"].append(g)
        return useful
