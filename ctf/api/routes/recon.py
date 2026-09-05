"""
API - Recon routes
"""
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from ctf.core.plugin import PluginRegistry
from ctf.core import database
from ctf.core.workspace import get_active

router = APIRouter()


def templates(request: Request):
    return request.app.state.templates


@router.get("/", response_class=HTMLResponse)
async def recon_page(request: Request):
    return templates(request).TemplateResponse(request, "recon.html", {"request": request})


@router.post("/scan", response_class=HTMLResponse)
async def port_scan(request: Request, target: str = Form(...), ports: str = Form("common")):
    plugin_cls = PluginRegistry.get("recon", "port_scan")
    plugin = plugin_cls()
    result = await plugin.execute(target, ports=ports)

    ws = get_active()
    if result.success:
        await database.save_result(ws, "recon", target, result.to_dict())

    return templates(request).TemplateResponse(request, "partials/scan_result.html", {
        "request": request,
        "result": result,
        "target": target,
    })
