"""
CTF Toolkit - Notes API Routes
"""
from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from ctf.core import database as db

notes_router = APIRouter()


def get_templates(request: Request):
    return request.app.state.templates


# ── Notes ──────────────────────────────────────────────────────────────────────

@notes_router.get("/", response_class=HTMLResponse)
async def notes_page(request: Request):
    ws = request.query_params.get("ws", "default")
    notes = await db.get_notes(ws)
    t = get_templates(request)
    return t.TemplateResponse(request, "notes.html", {
        "request": request,
        "notes": notes,
        "active_ws": ws,
    })


@notes_router.post("/add")
async def add_note(
    request: Request,
    title: str = Form(...),
    content: str = Form(...),
    tags: str = Form(""),
):
    ws = request.query_params.get("ws", "default")
    await db.add_note(ws, title, content, tags)
    return JSONResponse({"success": True})


@notes_router.post("/update")
async def update_note(
    request: Request,
    note_id: int = Form(...),
    title: str = Form(""),
    content: str = Form(""),
    tags: str = Form(""),
):
    ws = request.query_params.get("ws", "default")
    updates = {}
    if title:
        updates["title"] = title
    if content:
        updates["content"] = content
    if tags is not None:
        updates["tags"] = tags
    await db.update_note(ws, note_id, **updates)
    return JSONResponse({"success": True})


@notes_router.post("/delete")
async def delete_note(request: Request, note_id: int = Form(...)):
    ws = request.query_params.get("ws", "default")
    await db.delete_note(ws, note_id)
    return JSONResponse({"success": True})


@notes_router.get("/{note_id}", response_class=HTMLResponse)
async def get_note(request: Request, note_id: int):
    ws = request.query_params.get("ws", "default")
    note = await db.get_note(ws, note_id)
    if not note:
        raise HTTPException(404, "Note not found")
    t = get_templates(request)
    return t.TemplateResponse(request, "partials/note_detail.html", {
        "request": request,
        "note": note,
        "active_ws": ws,
    })