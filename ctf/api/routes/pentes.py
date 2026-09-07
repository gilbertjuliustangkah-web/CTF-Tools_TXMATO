"""
API - Pentest routes (subdomain enum, service probe, dir brute, auth brute, sqli/xss scan)
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
async def pentes_page(request: Request):
    return templates(request).TemplateResponse(request, "pentes.html", {
        "request": request,
        "active_ws": get_active(),
    })


@router.post("/subdomains", response_class=HTMLResponse)
async def subdomains(request: Request, domain: str = Form(...), wordlist: str = Form("")):
    plugin_cls = PluginRegistry.get("pentes", "subdomain_enum")
    ws = get_active()
    result = await plugin_cls().execute(domain, wordlist=wordlist, sandbox=ws)

    if result.success:
        await database.save_result(ws, "pentes", domain, result.to_dict())

    return templates(request).TemplateResponse(request, "partials/pentes_result.html", {
        "request": request,
        "result": result,
        "target": domain,
        "kind": "subdomains",
    })


@router.post("/probe", response_class=HTMLResponse)
async def probe(request: Request, target: str = Form(...), ports: str = Form("common")):
    plugin_cls = PluginRegistry.get("pentes", "service_probe")
    ws = get_active()
    result = await plugin_cls().execute(target, ports=ports)

    if result.success:
        await database.save_result(ws, "pentes", target, result.to_dict())

    return templates(request).TemplateResponse(request, "partials/pentes_result.html", {
        "request": request,
        "result": result,
        "target": target,
        "kind": "probe",
    })


@router.post("/dir", response_class=HTMLResponse)
async def dir_brute(request: Request, url: str = Form(...), wordlist: str = Form("")):
    plugin_cls = PluginRegistry.get("pentes", "dir_brute")
    ws = get_active()
    result = await plugin_cls().execute(url, wordlist=wordlist, sandbox=ws)

    if result.success:
        await database.save_result(ws, "pentes", url, result.to_dict())

    return templates(request).TemplateResponse(request, "partials/pentes_result.html", {
        "request": request,
        "result": result,
        "target": url,
        "kind": "dir",
    })


@router.post("/auth", response_class=HTMLResponse)
async def auth_brute(
    request: Request,
    url: str = Form(...),
    usernames: str = Form(""),
    passwords: str = Form(""),
    mode: str = Form("basic"),
    delay: float = Form(0.35),
    acknowledge: bool = Form(False),
):
    plugin_cls = PluginRegistry.get("pentes", "auth_brute")
    ws = get_active()
    result = await plugin_cls().execute(
        url,
        usernames=usernames,
        passwords=passwords,
        mode=mode,
        delay=delay,
        acknowledge=acknowledge,
    )

    if result.success:
        await database.save_result(ws, "pentes", url, result.to_dict())

    return templates(request).TemplateResponse(request, "partials/pentes_result.html", {
        "request": request,
        "result": result,
        "target": url,
        "kind": "auth",
    })


@router.post("/sqli", response_class=HTMLResponse)
async def sqli(request: Request, url: str = Form(...)):
    plugin_cls = PluginRegistry.get("pentes", "sqli_detect")
    ws = get_active()
    result = await plugin_cls().execute(url)

    if result.success:
        await database.save_result(ws, "pentes", url, result.to_dict())

    return templates(request).TemplateResponse(request, "partials/pentes_result.html", {
        "request": request,
        "result": result,
        "target": url,
        "kind": "sqli",
    })


@router.post("/xss", response_class=HTMLResponse)
async def xss(request: Request, url: str = Form(...)):
    plugin_cls = PluginRegistry.get("pentes", "xss_detect")
    ws = get_active()
    result = await plugin_cls().execute(url)

    if result.success:
        await database.save_result(ws, "pentes", url, result.to_dict())

    return templates(request).TemplateResponse(request, "partials/pentes_result.html", {
        "request": request,
        "result": result,
        "target": url,
        "kind": "xss",
    })
