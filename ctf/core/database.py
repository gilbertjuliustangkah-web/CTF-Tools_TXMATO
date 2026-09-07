"""
CTF Toolkit - Database Layer (SQLite async)
"""
import asyncio
import json
from pathlib import Path
from datetime import datetime
import aiosqlite

DB_PATH = Path("workspace") / "ctf.db"


async def get_db() -> aiosqlite.Connection:
    """Open a connection.

    NOTE: aiosqlite.Connection.__await__ starts its worker thread the first
    time the connection is awaited. Awaiting the same connection again (e.g.
    `async with await get_db()` or `async with get_db()` after an explicit
    await) raises "threads can only be started once". Callers must therefore
    await this exactly once and close it explicitly.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


async def _close(db: aiosqlite.Connection) -> None:
    try:
        await db.close()
    except Exception:
        pass


async def init_db():
    db = await get_db()
    try:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS workspaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                target_ip TEXT,
                target_domain TEXT,
                notes TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER NOT NULL,
                module TEXT NOT NULL,
                target TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
            );

            CREATE TABLE IF NOT EXISTS flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER NOT NULL,
                flag TEXT NOT NULL,
                description TEXT,
                found_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
            );

            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                filetype TEXT,
                notes TEXT,
                added_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
            );

            CREATE TABLE IF NOT EXISTS terminal_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER NOT NULL,
                command TEXT NOT NULL,
                output TEXT,
                exit_code INTEGER,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
            );

            CREATE TABLE IF NOT EXISTS python_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER NOT NULL,
                code TEXT NOT NULL,
                stdin TEXT,
                output TEXT,
                exit_code INTEGER,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
            );

            -- Default workspace
            INSERT OR IGNORE INTO workspaces (name, notes)
            VALUES ('default', 'Default workspace');
        """)
        await db.commit()
    finally:
        await _close(db)


# ── Workspace helpers ────────────────────────────────────────────────────────

async def list_workspaces() -> list[dict]:
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM workspaces ORDER BY created_at DESC")
        rows = await cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        await _close(db)


async def get_workspace(name: str) -> dict | None:
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM workspaces WHERE name = ?", (name,))
        row = await cur.fetchone()
        return dict(row) if row else None
    finally:
        await _close(db)


async def create_workspace(name: str, target_ip: str = "", target_domain: str = "") -> dict:
    db = await get_db()
    try:
        await db.execute(
            "INSERT OR IGNORE INTO workspaces (name, target_ip, target_domain) VALUES (?,?,?)",
            (name, target_ip, target_domain)
        )
        await db.commit()
    finally:
        await _close(db)
    return await get_workspace(name)


async def update_workspace(name: str, **kwargs) -> dict | None:
    allowed = {"target_ip", "target_domain", "notes"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return await get_workspace(name)
    setters = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [name]
    db = await get_db()
    try:
        await db.execute(
            f"UPDATE workspaces SET {setters}, updated_at = datetime('now') WHERE name = ?",
            values
        )
        await db.commit()
    finally:
        await _close(db)
    return await get_workspace(name)


# ── Scan result helpers ──────────────────────────────────────────────────────

async def save_result(workspace: str, module: str, target: str, result: dict) -> int:
    ws = await get_workspace(workspace)
    if not ws:
        ws = await create_workspace(workspace)
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO scan_results (workspace_id, module, target, result_json) VALUES (?,?,?,?)",
            (ws["id"], module, target, json.dumps(result))
        )
        await db.commit()
        return cur.lastrowid
    finally:
        await _close(db)


async def get_results(workspace: str, module: str | None = None) -> list[dict]:
    ws = await get_workspace(workspace)
    if not ws:
        return []
    db = await get_db()
    try:
        if module:
            cur = await db.execute(
                "SELECT * FROM scan_results WHERE workspace_id = ? AND module = ? ORDER BY created_at DESC",
                (ws["id"], module)
            )
        else:
            cur = await db.execute(
                "SELECT * FROM scan_results WHERE workspace_id = ? ORDER BY created_at DESC",
                (ws["id"],)
            )
        rows = await cur.fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["result"] = json.loads(d.pop("result_json"))
            out.append(d)
        return out
    finally:
        await _close(db)


# ── Flag helpers ─────────────────────────────────────────────────────────────

async def add_flag(workspace: str, flag: str, description: str = "") -> int:
    ws = await get_workspace(workspace)
    if not ws:
        ws = await create_workspace(workspace)
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO flags (workspace_id, flag, description) VALUES (?,?,?)",
            (ws["id"], flag, description)
        )
        await db.commit()
        return cur.lastrowid
    finally:
        await _close(db)


async def get_flags(workspace: str) -> list[dict]:
    ws = await get_workspace(workspace)
    if not ws:
        return []
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT * FROM flags WHERE workspace_id = ? ORDER BY found_at DESC",
            (ws["id"],)
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        await _close(db)


# ── Terminal history helpers ───────────────────────────────────────────────

async def add_terminal_command(workspace: str, command: str, output: str = "",
                               exit_code: int | None = None) -> int:
    """Persist one executed terminal command + its output to the workspace."""
    ws = await get_workspace(workspace)
    if not ws:
        ws = await create_workspace(workspace)
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO terminal_history (workspace_id, command, output, exit_code) VALUES (?,?,?,?)",
            (ws["id"], command, output, exit_code)
        )
        await db.commit()
        return cur.lastrowid
    finally:
        await _close(db)


async def get_terminal_history(workspace: str, limit: int = 50) -> list[dict]:
    ws = await get_workspace(workspace)
    if not ws:
        return []
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT id, command, output, exit_code, created_at "
            "FROM terminal_history WHERE workspace_id = ? "
            "ORDER BY created_at DESC, id DESC LIMIT ?",
            (ws["id"], int(limit))
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        await _close(db)


async def clear_terminal_history(workspace: str) -> int:
    ws = await get_workspace(workspace)
    if not ws:
        return 0
    db = await get_db()
    try:
        cur = await db.execute(
            "DELETE FROM terminal_history WHERE workspace_id = ?", (ws["id"],)
        )
        await db.commit()
        return cur.rowcount
    finally:
        await _close(db)


# ── Python box history helpers ──────────────────────────────────────────────

async def add_python_code(workspace: str, code: str, stdin: str = "",
                          output: str = "", exit_code: int | None = None) -> int:
    """Persist one executed Python snippet + its output to the workspace."""
    ws = await get_workspace(workspace)
    if not ws:
        ws = await create_workspace(workspace)
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO python_history (workspace_id, code, stdin, output, exit_code) VALUES (?,?,?,?,?)",
            (ws["id"], code, stdin, output, exit_code)
        )
        await db.commit()
        return cur.lastrowid
    finally:
        await _close(db)


async def get_python_history(workspace: str, limit: int = 50) -> list[dict]:
    ws = await get_workspace(workspace)
    if not ws:
        return []
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT id, code, stdin, output, exit_code, created_at "
            "FROM python_history WHERE workspace_id = ? "
            "ORDER BY created_at DESC, id DESC LIMIT ?",
            (ws["id"], int(limit))
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        await _close(db)


async def clear_python_history(workspace: str) -> int:
    ws = await get_workspace(workspace)
    if not ws:
        return 0
    db = await get_db()
    try:
        cur = await db.execute(
            "DELETE FROM python_history WHERE workspace_id = ?", (ws["id"],)
        )
        await db.commit()
        return cur.rowcount
    finally:
        await _close(db)