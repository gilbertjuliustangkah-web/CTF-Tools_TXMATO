"""
CTF Toolkit - Tools & Notes API Routes
"""
from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from ctf.core import database as db

router = APIRouter()


def get_templates(request: Request):
    return request.app.state.templates


# ── Tools ──────────────────────────────────────────────────────────────────────

@router.get("/tools-db", response_class=HTMLResponse)
async def tools_db_page(request: Request):
    ws = request.query_params.get("ws", "default")
    tools = await db.get_tools(ws)
    categories = sorted(set(t["category"] for t in tools if t["category"]))
    return get_templates(request).TemplateResponse("tools_db.html", {
        "request": request,
        "tools": tools,
        "categories": categories,
        "active_ws": ws,
    })


@router.post("/tools-db/add")
async def add_tool(
    request: Request,
    name: str = Form(...),
    command: str = Form(...),
    category: str = Form(""),
    description: str = Form(""),
    args_template: str = Form(""),
):
    ws = request.query_params.get("ws", "default")
    await db.add_tool(ws, name, command, category, description, args_template)
    return JSONResponse({"success": True})


@router.post("/tools-db/update")
async def update_tool(
    request: Request,
    tool_id: int = Form(...),
    name: str = Form(""),
    command: str = Form(""),
    category: str = Form(""),
    description: str = Form(""),
    args_template: str = Form(""),
):
    ws = request.query_params.get("ws", "default")
    updates = {}
    if name:
        updates["name"] = name
    if command:
        updates["command"] = command
    if category:
        updates["category"] = category
    if description:
        updates["description"] = description
    if args_template:
        updates["args_template"] = args_template
    await db.update_tool(ws, tool_id, **updates)
    return JSONResponse({"success": True})


@router.post("/tools-db/delete")
async def delete_tool(request: Request, tool_id: int = Form(...)):
    ws = request.query_params.get("ws", "default")
    await db.delete_tool(ws, tool_id)
    return JSONResponse({"success": True})


@router.post("/tools-db/run")
async def run_tool(request: Request, tool_id: int = Form(...), args: str = Form("")):
    ws = request.query_params.get("ws", "default")
    tool = await db.get_tool(ws, tool_id)
    if not tool:
        raise HTTPException(404, "Tool not found")

    from ctf.core.process import run as run_proc
    cmd = tool["command"]
    if args:
        cmd += f" {args}"
    elif tool["args_template"]:
        cmd += f" {tool['args_template']}"

    import shlex
    parts = shlex.split(cmd)
    result = await run_proc(*parts, timeout=60)
    return JSONResponse({
        "success": result.ok,
        "output": result.stdout,
        "error": result.stderr,
        "returncode": result.returncode,
    })


# ── Notes ──────────────────────────────────────────────────────────────────────

@router.get("/notes", response_class=HTMLResponse)
async def notes_page(request: Request):
    ws = request.query_params.get("ws", "default")
    notes = await db.get_notes(ws)
    return get_templates(request).TemplateResponse("notes.html", {
        "request": request,
        "notes": notes,
        "active_ws": ws,
    })


@router.post("/notes/add")
async def add_note(
    request: Request,
    title: str = Form(...),
    content: str = Form(...),
    tags: str = Form(""),
):
    ws = request.query_params.get("ws", "default")
    await db.add_note(ws, title, content, tags)
    return JSONResponse({"success": True})


@router.post("/notes/update")
async def update_note(
    request: Request,
    note_id: int = Form(...),
    title: str = Form(""),
    content: str = Form(""),
    tags: str = Form(""),
):
    ws = request.query_params.get("ws", "default")
    updates = {}
    if title:
        updates["title"] = title
    if content:
        updates["content"] = content
    if tags is not None:
        updates["tags"] = tags
    await db.update_note(ws, note_id, **updates)
    return JSONResponse({"success": True})


@router.post("/notes/delete")
async def delete_note(request: Request, note_id: int = Form(...)):
    ws = request.query_params.get("ws", "default")
    await db.delete_note(ws, note_id)
    return JSONResponse({"success": True})


@router.get("/notes/{note_id}", response_class=HTMLResponse)
async def get_note(request: Request, note_id: int):
    ws = request.query_params.get("ws", "default")
    note = await db.get_note(ws, note_id)
    if not note:
        raise HTTPException(404, "Note not found")
    return get_templates(request).TemplateResponse("partials/note_detail.html", {
        "request": request,
        "note": note,
        "active_ws": ws,
    })