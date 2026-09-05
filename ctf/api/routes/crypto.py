"""
API - Crypto routes
"""
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from ctf.core.plugin import PluginRegistry

router = APIRouter()


def templates(request: Request):
    return request.app.state.templates


@router.get("/", response_class=HTMLResponse)
async def crypto_page(request: Request):
    return templates(request).TemplateResponse(request, "crypto.html", {"request": request})


@router.post("/encode", response_class=HTMLResponse)
async def encode(
    request: Request,
    data: str = Form(...),
    mode: str = Form("detect"),
):
    plugin_cls = PluginRegistry.get("crypto", "encode")
    plugin = plugin_cls()
    result = await plugin.execute(data, mode=mode)

    return templates(request).TemplateResponse(request, "partials/crypto_result.html", {
        "request": request,
        "result": result,
        "mode": mode,
    })
