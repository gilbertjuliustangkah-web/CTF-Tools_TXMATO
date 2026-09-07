"""
CTF Toolkit - Workspace state manager
Persists the active workspace name to a local file.
"""
import re
from pathlib import Path

WORKSPACE_ROOT = Path("workspace")
_STATE_FILE = WORKSPACE_ROOT / ".active"
_TRAVERSAL_RE = re.compile(r"(?:^|[/\\])\.\.?(?:$|[/\\])")


def get_active() -> str:
    """Return the currently active workspace name."""
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if _STATE_FILE.exists():
        name = _STATE_FILE.read_text().strip()
        return name if name else "default"
    return "default"


def set_active(name: str):
    """Set the active workspace."""
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(name)


def sanitize_ws_name(name: str) -> str:
    """Strip path traversal / unsafe chars from a workspace name for file ops."""
    cleaned = "".join(c for c in (name or "") if c.isalnum() or c in "._- ").strip()
    if not cleaned or _TRAVERSAL_RE.search(cleaned):
        return "default"
    return cleaned


def resolve_workspace_path(name: str, base: Path = WORKSPACE_ROOT) -> Path:
    """Return a per-workspace directory, creating it if needed.

    All user-supplied file operations (uploads, forensic inspection) must be
    scoped to this directory so the web interface cannot read arbitrary files.
    """
    safe = sanitize_ws_name(name)
    path = (base / safe).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def is_within_workspace(path: Path, name: str, base: Path = WORKSPACE_ROOT) -> bool:
    """Check whether a resolved path is inside the given workspace directory."""
    ws_root = resolve_workspace_path(name, base=base)
    try:
        resolved = path.expanduser().resolve()
        return resolved.is_relative_to(ws_root)
    except (OSError, ValueError):
        return False


def resolve_sandboxed(target: str, sandbox: str | Path, base: Path = WORKSPACE_ROOT) -> Path | None:
    """Resolve `target` inside a sandbox directory.

    Used by modules that read files from disk so the web UI stays scoped to the
    active workspace. Returns the resolved Path, or None if the target would
    escape the sandbox.
    """
    if isinstance(sandbox, str):
        root = resolve_workspace_path(sandbox, base=base)
    else:
        root = Path(sandbox).expanduser().resolve()
    candidate = Path(target or "").expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve()
    if not candidate.is_relative_to(root):
        return None
    return candidate