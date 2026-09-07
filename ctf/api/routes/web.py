"""
API - Web recon routes
"""
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from ctf.core.plugin import PluginRegistry
from ctf.core import database
from ctf.core.workspace import get_active
from ctf.core.terminal import terminal

router = APIRouter()


def templates(request: Request):
    return request.app.state.templates


@router.get("/", response_class=HTMLResponse)
async def web_page(request: Request):
    return templates(request).TemplateResponse(request, "web.html", {"request": request})


@router.post("/headers", response_class=HTMLResponse)
async def headers_grab(request: Request, url: str = Form(...)):
    plugin_cls = PluginRegistry.get("web", "http_headers")
    result = await plugin_cls().execute(url)
    return templates(request).TemplateResponse(request, "partials/web_result.html", {
        "request": request,
        "result": result,
        "tab": "headers",
    })


@router.post("/robots", response_class=HTMLResponse)
async def robots(request: Request, url: str = Form(...)):
    plugin_cls = PluginRegistry.get("web", "robots_txt")
    result = await plugin_cls().execute(url)
    return templates(request).TemplateResponse(request, "partials/web_result.html", {
        "request": request,
        "result": result,
        "tab": "robots",
    })


@router.post("/jwt", response_class=HTMLResponse)
async def jwt(request: Request, token: str = Form(...)):
    plugin_cls = PluginRegistry.get("web", "jwt_decode")
    result = await plugin_cls().execute(token)
    return templates(request).TemplateResponse(request, "partials/web_result.html", {
        "request": request,
        "result": result,
        "tab": "jwt",
    })


@router.post("/cookies", response_class=HTMLResponse)
async def cookies(request: Request, cookie_string: str = Form(...)):
    plugin_cls = PluginRegistry.get("web", "cookie_inspect")
    result = await plugin_cls().execute(cookie_string)
    return templates(request).TemplateResponse(request, "partials/web_result.html", {
        "request": request,
        "result": result,
        "tab": "cookies",
    })


@router.post("/dir", response_class=HTMLResponse)
async def dir_enum(request: Request, url: str = Form(...)):
    plugin_cls = PluginRegistry.get("web", "dir_enum")
    result = await plugin_cls().execute(url)
    return templates(request).TemplateResponse(request, "partials/web_result.html", {
        "request": request,
        "result": result,
        "tab": "dir",
    })


# ── Web terminal (persistent WSL session) ──────────────────────────────────

def _term_ctx(request: Request, **extra) -> dict:
    ctx = {"request": request, "status": terminal.status()}
    ctx.update(extra)
    return ctx


@router.get("/terminal/status", response_class=HTMLResponse)
async def terminal_status(request: Request):
    return templates(request).TemplateResponse(
        request, "partials/terminal_result.html", _term_ctx(request, mode="status")
    )


@router.post("/terminal/start", response_class=HTMLResponse)
async def terminal_start(request: Request):
    out = await terminal.start()
    return templates(request).TemplateResponse(
        request, "partials/terminal_result.html", _term_ctx(request, mode="start", result=out)
    )


@router.post("/terminal/stop", response_class=HTMLResponse)
async def terminal_stop(request: Request):
    await terminal.stop()
    return templates(request).TemplateResponse(
        request, "partials/terminal_result.html", _term_ctx(request, mode="stop")
    )


@router.post("/terminal/run", response_class=HTMLResponse)
async def terminal_run(request: Request, command: str = Form(...)):
    ws = get_active()
    out = await terminal.run_command(command, timeout=60)
    if out["ok"]:
        await database.add_terminal_command(ws, out["command"], out.get("output", ""), out.get("exit_code"))
    history = await database.get_terminal_history(ws)
    return templates(request).TemplateResponse(
        request, "partials/terminal_result.html",
        _term_ctx(request, mode="run", result=out, history=history),
    )