"""
API - Reverse engineering routes
"""
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from ctf.core.plugin import PluginRegistry
from ctf.core.workspace import get_active, resolve_sandboxed

router = APIRouter()


def templates(request: Request):
    return request.app.state.templates


@router.get("/", response_class=HTMLResponse)
async def reverse_page(request: Request):
    return templates(request).TemplateResponse(request, "reverse.html", {
        "request": request,
        "active_ws": get_active(),
    })


@router.post("/info", response_class=HTMLResponse)
async def binary_info(request: Request, filepath: str = Form(...)):
    plugin_cls = PluginRegistry.get("reverse", "binary_info")
    ws = get_active()
    path = resolve_sandboxed(filepath, ws)
    result = await plugin_cls().execute(str(path), sandbox=ws)
    return templates(request).TemplateResponse(request, "partials/reverse_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/disasm", response_class=HTMLResponse)
async def disasm(request: Request, filepath: str = Form(...), length: int = Form(100)):
    plugin_cls = PluginRegistry.get("reverse", "disasm")
    path = resolve_sandboxed(filepath, get_active())
    result = await plugin_cls().execute(str(path), length=length)
    return templates(request).TemplateResponse(request, "partials/reverse_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/shellcode", response_class=HTMLResponse)
async def shellcode(request: Request, filepath: str = Form(...)):
    plugin_cls = PluginRegistry.get("reverse", "shellcode_extract")
    path = resolve_sandboxed(filepath, get_active())
    result = await plugin_cls().execute(str(path))
    return templates(request).TemplateResponse(request, "partials/reverse_result.html", {
        "request": request,
        "result": result,
    })