"""
CTF Toolkit - Python Code Runner

Executes user-supplied Python 3 source in a subprocess and captures stdout +
stderr (merged) with a per-run timeout. Runs in the active workspace directory
so the code can read/write workspace files. Nothing is evaluated in-process;
every run is a fresh interpreter, so code cannot access the app's memory/state.

Code is executed verbatim as written by the user, with the user's own
privileges. The dashboard is localhost + CSRF protected (plus an auth token
when bound beyond loopback) — treat this like a real Python shell.
"""
import asyncio
import sys
import time


class PythonRunner:
    DEFAULT_TIMEOUT = 30

    async def run(self, code: str = "", stdin: str = "", timeout: int = DEFAULT_TIMEOUT,
                  cwd: str | None = None) -> dict:
        raw = (stdin or "").encode("utf-8", errors="replace")
        return await self._execute(code, raw, timeout, cwd)

    async def _execute(self, code: str, raw_input: bytes, timeout: int, cwd: str | None) -> dict:
        if not (code or "").strip():
            return {"ok": False, "error": "No code to run."}
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-u", "-c", code,
                cwd=cwd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except Exception as e:
            return {"ok": False, "error": f"Failed to start interpreter: {e}"}

        start = time.monotonic()
        try:
            out_b, _ = await asyncio.wait_for(
                proc.communicate(input=raw_input), timeout=max(1, int(timeout))
            )
            done, timed_out = True, False
        except asyncio.TimeoutError:
            timed_out = True
            try:
                proc.kill()
            except Exception:
                pass
            out_b, _ = await proc.communicate()
            done = False

        duration = round(time.monotonic() - start, 2)
        output = out_b.decode("utf-8", errors="replace")
        if timed_out:
            output += f"\n[timeout] Interpreter killed after {int(timeout)}s."
        return {
            "ok": True,
            "code": code,
            "output": output.strip(),
            "exit_code": proc.returncode,
            "timed_out": timed_out,
            "duration": duration,
            "cwd": cwd or ".",
        }


python_runner = PythonRunner()