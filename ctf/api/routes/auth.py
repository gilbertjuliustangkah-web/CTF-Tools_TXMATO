"""
API - Authentication routes (token login)
"""
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from ctf.api import security

router = APIRouter()


def templates(request: Request):
    return request.app.state.templates


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates(request).TemplateResponse(request, "login.html", {"request": request})


@router.post("/login")
async def login(request: Request, token: str = Form(...)):
    if security.secure_eq(token, security.get_token()):
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            security.SESSION_COOKIE,
            security.sign_session(security.get_token()),
            httponly=True,
            samesite="lax",
            secure=False,
            max_age=60 * 60 * 24 * 7,
        )
        return response
    return templates(request).TemplateResponse(
        request, "login.html", {"request": request, "error": "Invalid token"}
    )
