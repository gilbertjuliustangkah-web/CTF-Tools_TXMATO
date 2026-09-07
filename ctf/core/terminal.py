"""
CTF Toolkit - WSL Terminal Manager

Maintains a persistent Linux shell session via WSL (`wsl.exe`). The flow is:
  * "start" spawns the WSL default distro shell and keeps it alive
  * "run" pipes a Linux CLI command into that same session and captures the
    output (stderr is merged into stdout), so consecutive commands share state
    (saved vars, cd'ed directories, spawned background jobs)
  * a unique sentinel line marks end-of-output for each command; a per-command
    timeout kills & restarts the session so a hung command cannot wedge it

Commands are executed verbatim as typed by the user, with the user's own
privileges. The dashboard is localhost + CSRF protected (plus an auth token
when bound beyond loopback) — treat this like a real shell.
"""
import asyncio
import re
import shutil
import uuid
from collections import deque

MAX_SAVED_LINES = 20000


class WslTerminal:
    """A single persistent WSL session. Only one is kept per running app."""

    def __init__(self):
        self.available = shutil.which("wsl") is not None
        self._proc: asyncio.subprocess.Process | None = None
        self._reader: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._lines: deque[str] = deque(maxlen=MAX_SAVED_LINES)
        self._sentinel = ""
        self._sentinel_idx: int | None = None
        self._sentinel_evt = asyncio.Event()

    # ── session management ────────────────────────────────────────────────

    async def start(self) -> dict:
        """(Re)spawn the WSL shell. Safe to call when already running."""
        if not self.available:
            return {"ok": False, "error": "wsl.exe not found in PATH"}
        async with self._lock:
            return await self._ensure_locked()

    async def _ensure_locked(self) -> dict:
        """Spawn the shell (caller must hold self._lock)."""
        if self._proc and self._proc.returncode is None:
            return {"ok": True, "started": False, "error": ""}
        await self._kill_locked()
        self._lines.clear()
        self._sentinel = ""
        self._sentinel_idx = None
        self._sentinel_evt = asyncio.Event()
        self._proc = await asyncio.create_subprocess_exec(
            "wsl",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._reader = asyncio.create_task(self._read_loop())
        return {"ok": True, "started": True, "error": ""}

    async def stop(self) -> dict:
        async with self._lock:
            await self._kill_locked()
            return {"ok": True}

    async def _kill_locked(self):
        proc, self._proc = self._proc, None
        if self._reader:
            self._reader.cancel()
            self._reader = None
        if proc and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass

    async def _read_loop(self):
        while True:
            try:
                line = await self._proc.stdout.readline()
            except Exception:
                break
            if not line:
                break
            self._lines.append(line.decode("utf-8", errors="replace").rstrip("\n"))
            if self._sentinel and self._sentinel in self._lines[-1] and not self._sentinel_evt.is_set():
                self._sentinel_idx = len(self._lines) - 1
                self._sentinel_evt.set()

    # ── command execution ─────────────────────────────────────────────────

    async def run_command(self, command: str, timeout: int = 60) -> dict:
        cmd = (command or "").strip()
        if not cmd:
            return {"ok": False, "error": "Empty command", "command": cmd}

        async with self._lock:
            started = await self._ensure_locked()
            if not started["ok"]:
                return {"ok": False, "error": started["error"], "command": cmd}
            assert self._proc and self._proc.stdin is not None

            marker = uuid.uuid4().hex[:8]
            rc_prefix = f"__CTF_RC_{marker}_"
            sentinel = f"__CTF_END_{marker}__"

            start = len(self._lines)
            self._sentinel = sentinel
            self._sentinel_idx = None
            self._sentinel_evt = asyncio.Event()

            try:
                self._proc.stdin.write(f"{cmd} 2>&1; echo {rc_prefix}$?__; echo {sentinel}\n".encode("utf-8"))
                await self._proc.stdin.drain()
            except Exception as e:
                self._sentinel = ""
                return {"ok": False, "error": f"Failed to write to session: {e}", "command": cmd}

            try:
                await asyncio.wait_for(self._sentinel_evt.wait(), timeout=max(1, int(timeout)))
                done = True
            except asyncio.TimeoutError:
                done = False
                self._sentinel = ""
                await self._kill_locked()

            end = self._sentinel_idx if self._sentinel_idx is not None else len(self._lines)
            self._sentinel = ""
            self._sentinel_idx = None

            raw = list(self._lines)[start:end]
            output, exit_code = self._extract_rc(raw, rc_prefix, done)
            if not done:
                output += "\n[timeout] Command exceeded the limit; WSL session was restarted."
            return {
                "ok": True,
                "command": cmd,
                "output": output.strip(),
                "exit_code": exit_code,
                "timed_out": not done,
                "session_alive": self._proc is not None and self._proc.returncode is None,
            }

    def _extract_rc(self, raw: list[str], rc_prefix: str, done: bool) -> tuple[str, int | None]:
        exit_code = None
        if done:
            for i in range(len(raw) - 1, -1, -1):
                if rc_prefix in raw[i]:
                    m = re.search(rf"{re.escape(rc_prefix)}(-?\d+)__", raw[i])
                    if m:
                        exit_code = int(m.group(1))
                    raw = raw[:i] + raw[i + 1:]
                    break
        return "\n".join(raw).strip(), exit_code

    def _parse_rc(self, line: str, rc_prefix: str) -> int | None:
        m = re.search(rf"{re.escape(rc_prefix)}(-?\d+)__", line)
        return int(m.group(1)) if m else None

    # ── introspection ─────────────────────────────────────────────────────

    def status(self) -> dict:
        running = self._proc is not None and self._proc.returncode is None
        return {
            "ok": True,
            "available": self.available,
            "running": running,
            "pid": self._proc.pid if running else None,
            "shell": "wsl" if self.available else "none",
        }


terminal = WslTerminal()