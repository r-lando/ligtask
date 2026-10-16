"""Supabase Auth verification; provider tokens stay in HttpOnly cookies."""

import os
from dataclasses import dataclass
from urllib.parse import urlparse
from uuid import UUID

import httpx
from fastapi import HTTPException, Request, Response

ACCESS_COOKIE = "talged_access"
REFRESH_COOKIE = "talged_refresh"


@dataclass(frozen=True)
class User:
    id: str
    email: str


def allowed_origins():
    return [value.strip() for value in os.getenv(
        "AUTH_ALLOWED_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173"
    ).split(",") if value.strip()]


def check_origin(request: Request):
    origin = request.headers.get("origin")
    if origin and origin not in allowed_origins():
        raise HTTPException(status_code=403, detail="Request origin is not allowed.")
    if request.cookies and not origin:
        raise HTTPException(status_code=403, detail="An Origin header is required.")


def provider_request(method, path, *, token=None, payload=None):
    url = os.getenv("SUPABASE_URL", "").rstrip("/")
    key = os.getenv("SUPABASE_PUBLISHABLE_KEY", "")
    parsed = urlparse(url)
    if not key or parsed.scheme != "https" or not parsed.hostname:
        raise HTTPException(status_code=503, detail="Authentication is not configured.")
    headers = {"apikey": key}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with httpx.Client(timeout=10, follow_redirects=False) as client:
            response = client.request(method, f"{url}/auth/v1/{path}", headers=headers, json=payload)
        if response.status_code == 429:
            raise HTTPException(status_code=429, detail="Too many sign-in attempts. Please retry later.")
        if response.status_code >= 500:
            raise HTTPException(status_code=503, detail="Authentication service is temporarily unavailable.")
        if not response.is_success:
            raise HTTPException(status_code=401, detail="Sign-in failed or session expired.")
        return response.json() if response.content else {}
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Authentication service is temporarily unavailable.") from exc


def user_from_data(data):
    try:
        user_id = str(UUID(data["id"]))
        email = data["email"]
        if not isinstance(email, str) or not email:
            raise ValueError()
        allowed = {value.strip().lower() for value in os.getenv("AUTH_ALLOWED_EMAILS", "").split(",") if value.strip()}
        if not allowed:
            raise HTTPException(status_code=503, detail="Invited users have not been configured.")
        if email.lower() not in allowed or not data.get("email_confirmed_at"):
            raise HTTPException(status_code=403, detail="This account does not have access. Contact your administrator.")
        return User(user_id, email)
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=401, detail="Invalid authentication session.") from exc


def require_user(request: Request):
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        check_origin(request)
    token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Please sign in.")
    return user_from_data(provider_request("GET", "user", token=token))


def set_session(response: Response, session):
    try:
        access, refresh = session["access_token"], session["refresh_token"]
        expires = int(session["expires_in"])
        user = user_from_data(session["user"])
        if not access or not refresh or expires <= 0:
            raise ValueError()
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=503, detail="Authentication service returned an invalid session.") from exc
    secure = os.getenv("AUTH_COOKIE_SECURE", "true").lower() != "false"
    response.set_cookie(ACCESS_COOKIE, access, max_age=expires, httponly=True,
                        secure=secure, samesite="lax", path="/")
    response.set_cookie(REFRESH_COOKIE, refresh, max_age=30 * 86400, httponly=True,
                        secure=secure, samesite="lax", path="/auth")
    response.headers["Cache-Control"] = "no-store"
    return {"id": user.id, "email": user.email}


def clear_session(response):
    response.delete_cookie(ACCESS_COOKIE, path="/")
    response.delete_cookie(REFRESH_COOKIE, path="/auth")
    response.headers["Cache-Control"] = "no-store"
