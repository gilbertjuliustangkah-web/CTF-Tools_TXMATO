"""
CTF Toolkit - Async subprocess runner
"""
import asyncio
import shutil
from dataclasses import dataclass


@dataclass
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


async def run(
    *args: str,
    timeout: int = 60,
    cwd: str | None = None,
) -> ProcessResult:
    """
    Run a command asynchronously.
    Returns ProcessResult(returncode, stdout, stderr).
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return ProcessResult(
            returncode=proc.returncode,
            stdout=stdout.decode(errors="replace").strip(),
            stderr=stderr.decode(errors="replace").strip(),
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass
        return ProcessResult(-1, "", f"Timeout after {timeout}s")
    except FileNotFoundError:
        return ProcessResult(-1, "", f"Command not found: {args[0]}")
    except Exception as e:
        return ProcessResult(-1, "", str(e))


def is_available(tool: str) -> bool:
    """Check if a system tool is available in PATH."""
    return shutil.which(tool) is not None
