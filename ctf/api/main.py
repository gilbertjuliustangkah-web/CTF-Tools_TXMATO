"""
CTF Toolkit - FastAPI Web App
"""
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates

# Register all plugins
import ctf.modules.recon.port_scan
import ctf.modules.crypto.encoder
import ctf.modules.forensic.file_inspect

from ctf.core import database
from ctf.api.routes import dashboard, recon, crypto, forensic, workspace, auth, tools
from ctf.api import security

HOST = os.environ.get("CTF_HOST", "127.0.0.1")
PORT = int(os.environ.get("CTF_PORT", "8080"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    await database.init_db()
    yield


app = FastAPI(title="CTF Toolkit", lifespan=lifespan)

TEMPLATES = Jinja2Templates(
    directory=Path(__file__).parent.parent.parent / "frontend" / "templates",
    context_processors=[lambda request: {
        "csrf_token": getattr(request.state, "csrf_token", ""),
        "auth_token": getattr(app.state, "auth_token", ""),
        "require_auth": bool(getattr(app.state, "require_auth", False)),
    }],
)

app.state.templates = TEMPLATES

# Install security (auth + CSRF) before serving.
app.add_middleware(security.SecurityMiddleware, host=HOST, port=PORT)
app.state.require_auth = security.require_auth_for(HOST)
app.state.auth_token = security._load_secrets()

# Mount routes
app.include_router(auth.router,       tags=["auth"])
app.include_router(dashboard.router,  tags=["dashboard"])
app.include_router(workspace.router,  prefix="/workspace",  tags=["workspace"])
app.include_router(recon.router,      prefix="/recon",      tags=["recon"])
app.include_router(crypto.router,     prefix="/crypto",     tags=["crypto"])
app.include_router(forensic.router,   prefix="/forensic",   tags=["forensic"])
app.include_router(tools.router,      prefix="/tools",      tags=["tools"])
