"""
API - Pwn routes
"""
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from ctf.core.plugin import PluginRegistry
from ctf.core.workspace import get_active

router = APIRouter()


def templates(request: Request):
    return request.app.state.templates


@router.get("/", response_class=HTMLResponse)
async def pwn_page(request: Request):
    return templates(request).TemplateResponse(request, "pwn.html", {
        "request": request,
        "active_ws": get_active(),
    })


@router.post("/checksec", response_class=HTMLResponse)
async def checksec(request: Request, filepath: str = Form(...)):
    plugin_cls = PluginRegistry.get("pwn", "checksec")
    ws = get_active()
    result = await plugin_cls().execute(filepath, sandbox=ws)
    return templates(request).TemplateResponse(request, "partials/pwn_checksec.html", {
        "request": request,
        "result": result,
    })


@router.post("/cyclic", response_class=HTMLResponse)
async def cyclic(request: Request, mode: str = Form(...), length: int = Form(200), pattern: str = Form("")):
    plugin_cls = PluginRegistry.get("pwn", "cyclic")
    result = await plugin_cls().execute("pwn", mode=mode, length=length, pattern=pattern)
    return templates(request).TemplateResponse(request, "partials/pwn_cyclic.html", {
        "request": request,
        "result": result,
    })


@router.post("/rop", response_class=HTMLResponse)
async def rop_search(request: Request, filepath: str = Form(...), search_term: str = Form("")):
    plugin_cls = PluginRegistry.get("pwn", "rop_search")
    ws = get_active()
    result = await plugin_cls().execute(filepath, search=search_term, sandbox=ws)
    return templates(request).TemplateResponse(request, "partials/pwn_rop.html", {
        "request": request,
        "result": result,
    })