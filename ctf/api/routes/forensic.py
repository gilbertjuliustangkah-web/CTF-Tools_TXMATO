"""
API - Forensic routes
"""
from pathlib import Path

from fastapi import APIRouter, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse

from ctf.core.plugin import PluginRegistry
from ctf.core.workspace import get_active, resolve_workspace_path, resolve_sandboxed

router = APIRouter()


def templates(request: Request):
    return request.app.state.templates


@router.get("/", response_class=HTMLResponse)
async def forensic_page(request: Request):
    return templates(request).TemplateResponse(request, "forensic.html", {
        "request": request,
        "active_ws": get_active(),
    })


@router.post("/upload", response_class=HTMLResponse)
async def upload_and_inspect(request: Request, file: UploadFile = File(...)):
    plugin_cls = PluginRegistry.get("forensic", "file_inspect")
    plugin = plugin_cls()

    ws = get_active()
    safe_name = Path(file.filename or "upload.bin").name
    target = resolve_workspace_path(ws) / safe_name
    with target.open("wb") as fh:
        fh.write(await file.read())

    result = await plugin.execute(str(target.resolve()), sandbox=ws)

    return templates(request).TemplateResponse(request, "partials/forensic_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/inspect", response_class=HTMLResponse)
async def inspect(request: Request, filepath: str = Form(...)):
    plugin_cls = PluginRegistry.get("forensic", "file_inspect")
    plugin = plugin_cls()

    ws = get_active()
    result = await plugin.execute(filepath, sandbox=ws)

    return templates(request).TemplateResponse(request, "partials/forensic_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/strings", response_class=HTMLResponse)
async def strings(request: Request, filepath: str = Form(...), min_len: int = Form(4)):
    path = resolve_sandboxed(filepath, get_active())
    plugin_cls = PluginRegistry.get("forensic", "strings_extract")
    result = await plugin_cls().execute(str(path), min_length=min_len)
    return templates(request).TemplateResponse(request, "partials/forensic_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/hash", response_class=HTMLResponse)
async def hash_calc(request: Request, filepath: str = Form(...)):
    path = resolve_sandboxed(filepath, get_active())
    plugin_cls = PluginRegistry.get("forensic", "hash_calc")
    result = await plugin_cls().execute(str(path))
    return templates(request).TemplateResponse(request, "partials/forensic_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/hexdump", response_class=HTMLResponse)
async def hexdump(request: Request, filepath: str = Form(...), offset: int = Form(0), length: int = Form(256)):
    path = resolve_sandboxed(filepath, get_active())
    plugin_cls = PluginRegistry.get("forensic", "hexdump_view")
    result = await plugin_cls().execute(str(path), offset=offset, length=length)
    return templates(request).TemplateResponse(request, "partials/forensic_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/pdf", response_class=HTMLResponse)
async def pdf_analyze(request: Request, filepath: str = Form(...)):
    path = resolve_sandboxed(filepath, get_active())
    plugin_cls = PluginRegistry.get("forensic", "pdf_analyze")
    result = await plugin_cls().execute(str(path))
    return templates(request).TemplateResponse(request, "partials/forensic_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/binwalk", response_class=HTMLResponse)
async def binwalk(request: Request, filepath: str = Form(...), mode: str = Form("signature")):
    path = resolve_sandboxed(filepath, get_active())
    plugin_cls = PluginRegistry.get("forensic", "binwalk_scan")
    result = await plugin_cls().execute(str(path), mode=mode)
    return templates(request).TemplateResponse(request, "partials/forensic_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/ole", response_class=HTMLResponse)
async def ole_analyze(request: Request, filepath: str = Form(...)):
    path = resolve_sandboxed(filepath, get_active())
    plugin_cls = PluginRegistry.get("forensic", "ole_analyze")
    result = await plugin_cls().execute(str(path))
    return templates(request).TemplateResponse(request, "partials/forensic_result.html", {
        "request": request,
        "result": result,
    })
