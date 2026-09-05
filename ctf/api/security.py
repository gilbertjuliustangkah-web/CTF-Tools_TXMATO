"""
API - Security helpers (auth token + CSRF).

Auth token:
    Not required when the server is bound to localhost only.
    If a `CTF_TOKEN` env var is set, it is always required.
    Otherwise, when bound to a non-local interface, a random token is
    generated, persisted to <workspace>/.token, and shown at startup.

    When auth is required, unauthenticated browsers are redirected to /login.
    Successful login sets a signed session cookie (HMAC over the token).

CSRF:
    Double-submit cookie. Every state-changing request (POST/PUT/DELETE) must
    include a matching token: `X-CSRF-Token` header, or a `csrf` field in an
    `application/x-www-form-urlencoded` body. Templates expose `csrf_token`.

    Implemented as a pure ASGI middleware: the request body is buffered and
    replayed to the application so FastAPI/Starlette can still parse forms
    (BaseHTTPMiddleware consumes the body and breaks form parsing).
"""
from __future__ import annotations

import hmac
import os
import secrets
import urllib.parse

from starlette.responses import JSONResponse, RedirectResponse

from ctf.core.workspace import WORKSPACE_ROOT

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
CSRF_COOKIE = "ctf_csrf"
SESSION_COOKIE = "ctf_session"
AUTH_HEADER = "X-Auth-Token"
AUTH_QUERY = "token"

_secret = secrets.token_urlsafe(32)
_auth_token: str | None = None


def _load_secrets() -> str:
    global _auth_token
    if _auth_token:
        return _auth_token
    env = os.environ.get("CTF_TOKEN", "").strip()
    if env:
        _auth_token = env
        return _auth_token
    token_file = WORKSPACE_ROOT / ".token"
    if token_file.exists():
        tok = token_file.read_text().strip()
        if tok:
            _auth_token = tok
            return _auth_token
    tok = secrets.token_urlsafe(24)
    WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
    token_file.write_text(tok)
    _auth_token = tok
    return _auth_token


def get_token() -> str:
    return _load_secrets()


def require_auth_for(host: str) -> bool:
    """Auth is required when bound beyond localhost (or coerced via env)."""
    hostloop = host in ("127.0.0.1", "localhost", "::1", "")
    return bool(os.environ.get("CTF_TOKEN")) or not hostloop


def secure_eq(a: str, b: str) -> bool:
    return bool(a and b and hmac.compare_digest(a, b))


def sign_session(payload: str) -> str:
    return hmac.new(_secret.encode(), payload.encode(), "sha256").hexdigest() + "." + payload


def verify_session(cookie: str) -> bool:
    if not cookie or "." not in cookie:
        return False
    sig, payload = cookie.rsplit(".", 1)
    expected = hmac.new(_secret.encode(), payload.encode(), "sha256").hexdigest()
    return hmac.compare_digest(sig, expected) and payload == get_token()


class SecurityMiddleware:
    """ASGI middleware implementing token auth + CSRF with body replay."""

    def __init__(self, app, *, host: str, port: int):
        self.app = app
        self.host = host
        self.port = port
        self.require_auth = require_auth_for(host)
        self.token = get_token()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = _Headers(scope)
        method = scope["method"]
        path = scope["path"]
        query = urllib.parse.parse_qs(scope.get("query_string", b"").decode())
        cookies = _parse_cookies(headers.get("cookie"))

        csrf_cookie = cookies.get(CSRF_COOKIE)
        csrf = csrf_cookie or self._make_csrf(scope)
        scope.setdefault("state", {})["csrf_token"] = csrf

        # ── Auth ─────────────────────────────────────────────────────────────
        if self.require_auth and not self._is_authed(headers, query, cookies):
            if path == "/login":
                pass  # login page is reachable pre-auth
            else:
                if headers.get("x-requested-with") or path.startswith(("/recon/", "/crypto/")):
                    response = JSONResponse(status_code=401, content={"detail": "Missing or invalid auth token."})
                    return await response(scope, receive, send)
                response = RedirectResponse(url="/login", status_code=303)
                return await response(scope, receive, send)

        # ── CSRF (state-changing requests only) ──────────────────────────────
        body = None
        if method not in SAFE_METHODS:
            supplied = headers.get("x-csrf-token")
            if not supplied and _is_form_body(headers):
                body = await _receive_body(receive)
                supplied = _parse_csrf(body, headers.get("content-type", ""))
            if not secure_eq(supplied, csrf_cookie or ""):
                response = JSONResponse(status_code=403, content={"detail": "CSRF validation failed."})
                return await response(scope, receive, send)

        # ── Forward to the application, replaying buffered body if needed ────
        need_replay = body is not None

        async def new_receive():
            if need_replay:
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        async def new_send(message):
            if csrf_cookie is None and message["type"] == "http.response.start":
                message = dict(message)
                headers_list = list(message["headers"])
                setcookie = (
                    f"{CSRF_COOKIE}={csrf}; Path=/; Max-Age=2592000; "
                    "SameSite=lax"
                ).encode("latin-1")
                headers_list.append((b"set-cookie", setcookie))
                message["headers"] = headers_list
            await send(message)

        await self.app(scope, new_receive, new_send)

    def _make_csrf(self, scope) -> str:
        client = (scope.get("client") or ("",))[0]
        raw = self.token + client
        return hmac.new(_secret.encode(), raw.encode(), "sha256").hexdigest()

    def _is_authed(self, headers, query, cookies) -> bool:
        if verify_session(cookies.get(SESSION_COOKIE, "")):
            return True
        supplied = headers.get(AUTH_HEADER.lower()) or (query.get(AUTH_QUERY) or [""])[0]
        return secure_eq(supplied, self.token)


# ── Small ASGI helpers ───────────────────────────────────────────────────────

async def _receive_body(receive):
    chunks = []
    while True:
        msg = await receive()
        chunks.append(msg.get("body", b""))
        if not msg.get("more_body"):
            break
    return b"".join(chunks)


def _is_form_body(headers) -> bool:
    ct = headers.get("content-type", "")
    return "x-www-form-urlencoded" in ct or "multipart/form-data" in ct


def _parse_csrf(body: bytes, content_type: str) -> str:
    """Extract the `csrf` field from a urlencoded or multipart body."""
    if "x-www-form-urlencoded" in content_type or (not content_type and b"=" in body):
        form = urllib.parse.parse_qs(body.decode(errors="replace"))
        return (form.get("csrf") or [""])[0]

    # multipart/form-data: locate the boundary and scan parts for name="csrf".
    boundary = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part[len("boundary="):].strip('"')
            break
    if not boundary:
        return ""
    delim = f"--{boundary}".encode()
    for chunk in body.split(delim):
        sep = chunk.find(b"\r\n\r\n")
        if sep == -1:
            continue
        part_headers = chunk[:sep].decode(errors="replace").lower()
        if 'name="csrf"' in part_headers:
            value = chunk[sep + 4:]
            value = value.rstrip(b"\r\n")
            # Trim the trailing "--" terminator if this was the last part.
            if value.endswith(b"--"):
                value = value[:-2]
            return value.decode(errors="replace").strip()
    return ""


class _Headers:
    """Minimal case-insensitive header map built from the ASGI HTTP headers."""

    def __init__(self, scope):
        self._map = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }

    def get(self, name: str, default=""):
        return self._map.get(name.lower(), default)


def _parse_cookies(header: str | None) -> dict[str, str]:
    out = {}
    if not header:
        return out
    for part in header.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out[k.strip()] = v.strip()
    return out