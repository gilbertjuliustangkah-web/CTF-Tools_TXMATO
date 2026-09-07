"""
API - Python Box routes (write & run Python 3 in the browser)
"""
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from ctf.core import database
from ctf.core.workspace import get_active, resolve_workspace_path
from ctf.core.python_runner import python_runner

router = APIRouter()


def templates(request: Request):
    return request.app.state.templates


@router.get("/", response_class=HTMLResponse)
async def pybox_page(request: Request):
    return templates(request).TemplateResponse(request, "python.html", {
        "request": request,
        "active_ws": get_active(),
    })


@router.post("/run", response_class=HTMLResponse)
async def pybox_run(request: Request, code: str = Form(...),
                    stdin: str = Form(""), timeout: int = Form(30)):
    ws = get_active()
    cwd = str(resolve_workspace_path(ws))
    result = await python_runner.run(code=code, stdin=stdin, timeout=timeout, cwd=cwd)

    if result["ok"]:
        await database.add_python_code(ws, result["code"], stdin,
                                       result.get("output", ""), result.get("exit_code"))
    history = await database.get_python_history(ws)

    return templates(request).TemplateResponse(request, "partials/python_result.html", {
        "request": request,
        "result": result,
        "history": history,
        "active_ws": ws,
    })


@router.post("/clear", response_class=HTMLResponse)
async def pybox_clear(request: Request):
    ws = get_active()
    cleared = await database.clear_python_history(ws)
    return templates(request).TemplateResponse(request, "partials/python_result.html", {
        "request": request,
        "cleared": cleared,
        "active_ws": ws,
    })