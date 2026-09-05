"""
CTF Toolkit - Plugin Base Interface
Every module/plugin must extend PluginBase.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PluginResult:
    """Standardized result returned by every plugin."""
    module: str
    plugin: str
    target: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    raw: str = ""

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "plugin": self.plugin,
            "target": self.target,
            "success": self.success,
            "data": self.data,
            "error": self.error,
        }


class PluginBase(ABC):
    """
    Base class for all CTF Toolkit plugins.

    Subclass this, set the class attributes, and implement
    execute() and parse().
    """
    # Required class attributes
    name: str = ""          # e.g. "port_scan"
    description: str = ""  # short description
    category: str = ""      # recon | web | crypto | forensic | reverse | pwn
    version: str = "0.1.0"

    @abstractmethod
    async def execute(self, target: str, **kwargs) -> PluginResult:
        """Run the plugin against target. Must return a PluginResult."""
        ...

    @abstractmethod
    def parse(self, raw_output: str) -> dict:
        """Parse raw tool output into structured dict."""
        ...

    def info(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "version": self.version,
        }


# ── Registry ─────────────────────────────────────────────────────────────────

class PluginRegistry:
    _plugins: dict[str, type[PluginBase]] = {}

    @classmethod
    def register(cls, plugin_cls: type[PluginBase]):
        key = f"{plugin_cls.category}.{plugin_cls.name}"
        cls._plugins[key] = plugin_cls
        return plugin_cls

    @classmethod
    def get(cls, category: str, name: str) -> type[PluginBase] | None:
        return cls._plugins.get(f"{category}.{name}")

    @classmethod
    def list_all(cls) -> list[dict]:
        return [p().info() for p in cls._plugins.values()]

    @classmethod
    def list_category(cls, category: str) -> list[dict]:
        return [
            p().info()
            for key, p in cls._plugins.items()
            if key.startswith(f"{category}.")
        ]


# Decorator shorthand
def register_plugin(cls: type[PluginBase]):
    return PluginRegistry.register(cls)
