"""
CTF Toolkit - Tools API Routes
"""
from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from ctf.core import database as db

tools_router = APIRouter()


def get_templates(request: Request):
    return request.app.state.templates


# ── Tools ──────────────────────────────────────────────────────────────────────

@tools_router.get("/", response_class=HTMLResponse)
async def tools_db_page(request: Request):
    ws = request.query_params.get("ws", "default")
    tools = await db.get_tools(ws)
    categories = sorted(set(t["category"] for t in tools if t["category"]))
    t = get_templates(request)
    return t.TemplateResponse(request, "tools_db.html", {
        "request": request,
        "tools": tools,
        "categories": categories,
        "active_ws": ws,
    })


@tools_router.post("/add")
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


@tools_router.post("/update")
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


@tools_router.post("/delete")
async def delete_tool(request: Request, tool_id: int = Form(...)):
    ws = request.query_params.get("ws", "default")
    await db.delete_tool(ws, tool_id)
    return JSONResponse({"success": True})


@tools_router.post("/run")
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