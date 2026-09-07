"""
Web - Cookie Inspector Plugin
Parse and analyze HTTP cookies.
"""
import time
from ctf.core.plugin import PluginBase, PluginResult, register_plugin


@register_plugin
class CookieInspect(PluginBase):
    name = "cookie_inspect"
    description = "Parse HTTP Set-Cookie headers: security flags, session analysis"
    category = "web"

    async def execute(self, target: str, **kwargs) -> PluginResult:
        cookie_string = target.strip()
        cookies = self._parse_cookies(cookie_string)

        security_notes = []
        for cookie in cookies:
            if not cookie.get("secure"):
                security_notes.append(f"'{cookie['name']}' missing Secure flag")
            if not cookie.get("httponly"):
                security_notes.append(f"'{cookie['name']}' missing HttpOnly flag")
            if cookie.get("samesite", "").lower() == "none":
                security_notes.append(f"'{cookie['name']}' SameSite=None (CSRF risk)")
            if cookie.get("max_age", 0) > 86400 * 365:
                security_notes.append(f"'{cookie['name']}' very long expiry ({cookie['max_age']}s)")

        return PluginResult(
            module="web", plugin="cookie_inspect", target="",
            success=True,
            data={
                "cookies": cookies,
                "count": len(cookies),
                "security_notes": security_notes,
            }
        )

    def parse(self, raw_output: str) -> dict:
        return {"raw": raw_output}

    def _parse_cookies(self, cookie_string: str) -> list[dict]:
        cookies = []
        parts = [p.strip() for p in cookie_string.split(";")]

        for part in parts:
            if "=" not in part:
                continue
            name, _, value = part.partition("=")
            name = name.strip()
            value = value.strip().strip('"')

            cookie = {
                "name": name,
                "value": value[:100] + ("..." if len(value) > 100 else ""),
                "secure": False,
                "httponly": False,
                "samesite": "None",
                "path": "/",
                "domain": "",
                "max_age": 0,
            }

            lower_part = part.lower()
            if "secure" in lower_part.split(";"):
                cookie["secure"] = True
            if "httponly" in lower_part.split(";"):
                cookie["httponly"] = True

            cookies.append(cookie)

        if not cookies and cookie_string:
            cookies.append({
                "name": "(raw)", "value": cookie_string[:200],
                "secure": False, "httponly": False,
                "samesite": "None", "path": "/", "domain": "",
                "max_age": 0,
            })

        return cookies
