"""
API - ExifTool routes (full metadata GUI)
"""
from pathlib import Path

from fastapi import APIRouter, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, PlainTextResponse

from ctf.core.plugin import PluginRegistry
from ctf.core.workspace import get_active, resolve_workspace_path

router = APIRouter()


def templates(request: Request):
    return request.app.state.templates


@router.get("/", response_class=HTMLResponse)
async def exiftool_page(request: Request):
    return templates(request).TemplateResponse(request, "exiftool.html", {
        "request": request,
        "active_ws": get_active(),
    })


@router.post("/upload", response_class=HTMLResponse)
async def exiftool_upload(request: Request, file: UploadFile = File(...)):
    ws = get_active()
    safe_name = Path(file.filename or "upload.bin").name
    target = resolve_workspace_path(ws) / safe_name
    with target.open("wb") as fh:
        fh.write(await file.read())

    plugin_cls = PluginRegistry.get("forensic", "exiftool_gui")
    result = await plugin_cls().execute(str(target.resolve()), mode="read", sandbox=ws)

    return templates(request).TemplateResponse(request, "partials/exiftool_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/read", response_class=HTMLResponse)
async def exiftool_read(request: Request, filepath: str = Form(...)):
    ws = get_active()
    plugin_cls = PluginRegistry.get("forensic", "exiftool_gui")
    result = await plugin_cls().execute(filepath, mode="read", sandbox=ws)

    return templates(request).TemplateResponse(request, "partials/exiftool_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/edit", response_class=HTMLResponse)
async def exiftool_edit(
    request: Request,
    filepath: str = Form(...),
    tag_name: str = Form(...),
    tag_value: str = Form(...),
):
    ws = get_active()
    plugin_cls = PluginRegistry.get("forensic", "exiftool_gui")
    result = await plugin_cls().execute(
        filepath, mode="edit", tag_name=tag_name, tag_value=tag_value, sandbox=ws
    )

    return templates(request).TemplateResponse(request, "partials/exiftool_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/delete", response_class=HTMLResponse)
async def exiftool_delete(
    request: Request,
    filepath: str = Form(...),
    tag_name: str = Form(...),
):
    ws = get_active()
    plugin_cls = PluginRegistry.get("forensic", "exiftool_gui")
    result = await plugin_cls().execute(
        filepath, mode="delete", tag_name=tag_name, sandbox=ws
    )

    return templates(request).TemplateResponse(request, "partials/exiftool_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/export", response_class=PlainTextResponse)
async def exiftool_export(
    request: Request,
    filepath: str = Form(...),
    format: str = Form("json"),
):
    ws = get_active()
    plugin_cls = PluginRegistry.get("forensic", "exiftool_gui")
    result = await plugin_cls().execute(filepath, mode=f"export_{format}", sandbox=ws)

    if not result.success:
        return PlainTextResponse(result.error, status_code=400)

    content = result.data.get("content", "")
    media_type = "application/json" if format == "json" else "text/csv"
    from fastapi.responses import Response
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="metadata.{format}"'},
    )
