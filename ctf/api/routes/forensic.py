"""
API - Forensic routes
"""
from pathlib import Path

from fastapi import APIRouter, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse

from ctf.core.plugin import PluginRegistry
from ctf.core.workspace import get_active, resolve_workspace_path

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
