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
import ctf.modules.recon.dns_lookup
import ctf.modules.recon.whois_lookup
import ctf.modules.recon.ssl_check
import ctf.modules.crypto.encoder
import ctf.modules.crypto.hash_id
import ctf.modules.crypto.caesar
import ctf.modules.crypto.xor_tool
import ctf.modules.crypto.rsa_analyze
import ctf.modules.crypto.freq_analysis
import ctf.modules.forensic.file_inspect
import ctf.modules.forensic.binwalk_scan
import ctf.modules.forensic.strings_extract
import ctf.modules.forensic.hash_calc
import ctf.modules.forensic.hexdump_view
import ctf.modules.forensic.pdf_analyze
import ctf.modules.forensic.ole_analyze
import ctf.modules.forensic.volatility_analyze
import ctf.modules.forensic.exiftool_gui
import ctf.modules.web.http
import ctf.modules.web.jwt_decode
import ctf.modules.web.cookies
import ctf.modules.web.dir_enum
import ctf.modules.reverse.binary_info
import ctf.modules.reverse.disasm
import ctf.modules.reverse.shellcode_extract
import ctf.modules.pwn.checksec
import ctf.modules.pwn.cyclic
import ctf.modules.pwn.rop_search
import ctf.modules.stego.steg_detect
import ctf.modules.pentes.subdomain_enum
import ctf.modules.pentes.service_probe
import ctf.modules.pentes.dir_brute
import ctf.modules.pentes.auth_brute
import ctf.modules.pentes.sqli_detect
import ctf.modules.pentes.xss_detect

from ctf.core import database
from ctf.api.routes import dashboard, recon, crypto, forensic, workspace, auth, tools, web, reverse, pwn, stego, exiftool, pentes, pybox
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
app.include_router(web.router,        prefix="/web",        tags=["web"])
app.include_router(reverse.router,    prefix="/reverse",    tags=["reverse"])
app.include_router(pwn.router,        prefix="/pwn",        tags=["pwn"])
app.include_router(stego.router,      prefix="/stego",      tags=["stego"])
app.include_router(exiftool.router,   prefix="/exiftool",   tags=["exiftool"])
app.include_router(pentes.router,     prefix="/pentes",     tags=["pentes"])
app.include_router(pybox.router,      prefix="/python",     tags=["python"])
