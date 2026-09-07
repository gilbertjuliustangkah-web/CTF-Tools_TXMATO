"""
API - Steganography routes
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
async def stego_page(request: Request):
    return templates(request).TemplateResponse(request, "stego.html", {
        "request": request,
        "active_ws": get_active(),
    })


@router.post("/upload", response_class=HTMLResponse)
async def stego_upload(request: Request, file: UploadFile = File(...)):
    ws = get_active()
    safe_name = Path(file.filename or "upload.bin").name
    target = resolve_workspace_path(ws) / safe_name
    with target.open("wb") as fh:
        fh.write(await file.read())

    plugin_cls = PluginRegistry.get("stego", "steg_detect")
    result = await plugin_cls().execute(str(target.resolve()))

    return templates(request).TemplateResponse(request, "partials/stego_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/detect", response_class=HTMLResponse)
async def stego_detect(request: Request, filepath: str = Form(...)):
    ws = get_active()
    path = resolve_sandboxed(filepath, ws)
    plugin_cls = PluginRegistry.get("stego", "steg_detect")
    result = await plugin_cls().execute(str(path))

    return templates(request).TemplateResponse(request, "partials/stego_result.html", {
        "request": request,
        "result": result,
    })
