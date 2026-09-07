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


@router.post("/hash-id", response_class=HTMLResponse)
async def hash_identify(request: Request, hash_str: str = Form(...)):
    plugin_cls = PluginRegistry.get("crypto", "hash_id")
    result = await plugin_cls().execute(hash_str)
    return templates(request).TemplateResponse(request, "partials/crypto_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/caesar", response_class=HTMLResponse)
async def caesar(request: Request, text: str = Form(...), shift: int = Form(-1)):
    plugin_cls = PluginRegistry.get("crypto", "caesar_brute")
    result = await plugin_cls().execute(text, shift=None if shift < 0 else shift)
    return templates(request).TemplateResponse(request, "partials/crypto_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/xor", response_class=HTMLResponse)
async def xor(request: Request, data: str = Form(...), key: str = Form("")):
    plugin_cls = PluginRegistry.get("crypto", "xor_tool")
    result = await plugin_cls().execute(data, mode="decrypt", key=key)
    return templates(request).TemplateResponse(request, "partials/crypto_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/rsa", response_class=HTMLResponse)
async def rsa(request: Request, data: str = Form(...)):
    plugin_cls = PluginRegistry.get("crypto", "rsa_analyze")
    result = await plugin_cls().execute(data)
    return templates(request).TemplateResponse(request, "partials/crypto_result.html", {
        "request": request,
        "result": result,
    })


@router.post("/freq", response_class=HTMLResponse)
async def freq(request: Request, text: str = Form(...)):
    plugin_cls = PluginRegistry.get("crypto", "freq_analysis")
    result = await plugin_cls().execute(text)
    return templates(request).TemplateResponse(request, "partials/crypto_result.html", {
        "request": request,
        "result": result,
    })
