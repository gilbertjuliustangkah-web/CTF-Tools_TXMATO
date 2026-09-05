"""
API - Tool catalog & manager routes (HTML via HTMX)
"""
from html import escape

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from ctf.core.toolbox import (
    CATEGORY_LABELS,
    check_status,
    get_entry,
    grouped_state,
    install_tool,
    uninstall_tool,
)

router = APIRouter()


def templates(request: Request):
    return request.app.state.templates


@router.get("/", response_class=HTMLResponse)
async def tools_page(request: Request):
    groups, summary = grouped_state()
    return templates(request).TemplateResponse(request, "tools.html", {
        "request": request,
        "groups": groups,
        "summary": summary,
        "category_labels": CATEGORY_LABELS,
    })


def _card(request: Request, entry=None, job=None, error: str = ""):
    status = check_status(entry) if entry else None
    return templates(request).TemplateResponse(request, "partials/tool_card.html", {
        "request": request,
        "entry": entry,
        "status": status,
        "job": job,
        "error": error,
    })


@router.post("/install", response_class=HTMLResponse)
async def tool_install(request: Request, tool_id: str = Form(...)):
    entry = get_entry(tool_id)
    if not entry:
        return HTMLResponse(f'<div class="msg-error">{escape(tool_id)}: unknown tool</div>')
    job = await install_tool(tool_id)
    job = {**job, "action": "install"}
    return _card(request, entry=entry, job=job)


@router.post("/uninstall", response_class=HTMLResponse)
async def tool_uninstall(request: Request, tool_id: str = Form(...)):
    entry = get_entry(tool_id)
    if not entry:
        return HTMLResponse(f'<div class="msg-error">{escape(tool_id)}: unknown tool</div>')
    job = await uninstall_tool(tool_id)
    job = {**job, "action": "uninstall"}
    return _card(request, entry=entry, job=job)