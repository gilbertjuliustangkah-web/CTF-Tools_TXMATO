"""
Pentest - Login Brute-Force Plugin

Attempts credential pairs against an HTTP login endpoint (Basic auth or a JSON
form POST). Designed for USE ONLY against systems you are authorized to test
(e.g. local CTF labs). Safety rails are mandatory:

  * the caller must pass acknowledge=True (an explicit UI acknowledgment)
  * attempts are rate-limited (delay between guesses)
  * a hard cap on the number of attempts
  * input validated so nothing is ever passed through a shell
"""
import asyncio
import base64
import json

import httpx

from ctf.core.plugin import PluginBase, PluginResult, register_plugin

DEFAULT_DELAY = 0.35      # seconds between attempts (rate limit)
MAX_ATTEMPTS = 10000       # hard cap


@register_plugin
class AuthBrute(PluginBase):
    name = "auth_brute"
    description = "Brute-force HTTP login (Basic or JSON form). Authorized targets only."
    category = "pentes"

    async def execute(
        self,
        target: str,
        usernames: str = "",
        passwords: str = "",
        mode: str = "basic",
        delay: float = DEFAULT_DELAY,
        max_attempts: int = MAX_ATTEMPTS,
        acknowledge: bool = False,
        **kwargs,
    ) -> PluginResult:
        if not acknowledge:
            return PluginResult(
                module="pentes", plugin="auth_brute", target=target,
                success=False,
                error="Brute-forcing requires explicit acknowledgment. " +
                      "Only use this against systems you are authorized to test."
            )

        url = (target or "").strip().rstrip("/")
        if not (url.startswith("http://") or url.startswith("https://")) or len(url) < 9:
            return PluginResult(
                module="pentes", plugin="auth_brute", target=target,
                success=False, error=f"Invalid URL: '{target}'"
            )

        users = [u.strip() for u in (usernames or "").splitlines() if u.strip()]
        pwds = [p.strip() for p in (passwords or "").splitlines() if p.strip()]
        if not users or not pwds:
            return PluginResult(
                module="pentes", plugin="auth_brute", target=target,
                success=False, error="Provide at least one username and one password."
            )

        delay = min(max(float(delay or 0), 0.05), 5.0)
        tries = min(int(max_attempts or MAX_ATTEMPTS), MAX_ATTEMPTS)

        found = []
        attempted = 0
        stopped = False

        async with httpx.AsyncClient(follow_redirects=False,
                                     timeout=httpx.Timeout(8.0)) as client:
            for user in users:
                if stopped:
                    break
                for pwd in pwds:
                    if attempted >= tries:
                        stopped = True
                        break
                    attempted += 1
                    ok, detail, status = await self._try(client, url, user, pwd, mode)
                    if ok:
                        found.append({"username": user, "password": pwd,
                                      "note": detail, "status": status})
                        # Found the first pair; keep going a little to catch
                        # shared/multiple creds but cap the findings.
                        if len(found) >= 3:
                            stopped = True
                            break
                    if delay:
                        await asyncio.sleep(delay)

        return PluginResult(
            module="pentes", plugin="auth_brute", target=url,
            success=True,
            data={
                "url": url,
                "mode": mode,
                "found": found,
                "attempted": attempted,
                "cap_reached": stopped,
                "usernames_tested": len(users),
                "passwords_tested": len(pwds),
            },
        )

    async def _try(self, client, url: str, user: str, pwd: str, mode: str):
        """Return (success, detail, status) for one credential pair."""
        try:
            if mode == "basic":
                token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                resp = await client.get(url, headers={"Authorization": f"Basic {token}"})
                if resp.status_code in (200, 204):
                    return True, f"HTTP {resp.status_code}", resp.status_code
                return False, "", resp.status_code

            # JSON form login POST
            resp = await client.post(
                url,
                json={"username": user, "password": pwd},
                headers={"Content-Type": "application/json"},
            )
            ct = (resp.headers.get("content-type") or "").lower()
            if resp.status_code in (200, 201) and "json" in ct:
                try:
                    body = resp.json()
                except Exception:
                    body = {}
                # Heuristic success: no error key & non-empty payload.
                if not isinstance(body, dict) or not self._looks_like_error(body):
                    return True, "JSON login accepted", resp.status_code
            elif "basic" in ct and resp.status_code == 200:
                return True, "Basic challenge accepted", resp.status_code
            return False, "", resp.status_code
        except (httpx.HTTPError, httpx.TimeoutException):
            return False, "", 0

    def _looks_like_error(self, body: dict) -> bool:
        text = json.dumps(body).lower()
        for key in ("error", "message", "fail", "invalid", "wrong", "denied"):
            if key in text:
                return True
        return False

    def parse(self, raw_output: str) -> dict:
        found = []
        for line in raw_output.splitlines():
            if ":" in line and line.count(":") == 1:
                u, p = line.split(":", 1)
                found.append({"username": u, "password": p})
        return {"found": found}
