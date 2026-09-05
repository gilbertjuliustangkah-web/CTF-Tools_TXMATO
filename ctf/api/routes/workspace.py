"""
API - Workspace routes
"""
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from ctf.core import database
from ctf.core.workspace import get_active, set_active

router = APIRouter()


def templates(request: Request):
    return request.app.state.templates


@router.post("/switch")
async def switch_workspace(name: str = Form(...)):
    set_active(name)
    return RedirectResponse("/", status_code=303)


@router.post("/new")
async def new_workspace(
    name: str = Form(...),
    target_ip: str = Form(""),
    target_domain: str = Form(""),
):
    await database.create_workspace(name, target_ip, target_domain)
    set_active(name)
    return RedirectResponse("/", status_code=303)


@router.post("/flag")
async def add_flag(
    request: Request,
    flag: str = Form(...),
    description: str = Form(""),
):
    ws = get_active()
    await database.add_flag(ws, flag, description)
    return RedirectResponse("/", status_code=303)
