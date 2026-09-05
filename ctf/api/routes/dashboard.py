"""
API - Dashboard routes (HTML via HTMX)
"""
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ctf.core import database
from ctf.core.workspace import get_active

router = APIRouter()


def templates(request: Request):
    return request.app.state.templates


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    ws_name = get_active()
    ws = await database.get_workspace(ws_name) or {}
    results = await database.get_results(ws_name)
    flags = await database.get_flags(ws_name)
    workspaces = await database.list_workspaces()

    return templates(request).TemplateResponse(request, "index.html", {
        "request": request,
        "active_ws": ws_name,
        "workspace": ws,
        "results": results[:20],
        "flags": flags,
        "workspaces": workspaces,
    })


@router.get("/partial/results", response_class=HTMLResponse)
async def partial_results(request: Request):
    ws_name = get_active()
    results = await database.get_results(ws_name)
    return templates(request).TemplateResponse(request, "partials/results.html", {
        "request": request,
        "results": results[:20],
    })
