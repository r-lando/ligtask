from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, SecretStr

from app.services.auth_service import (
    REFRESH_COOKIE, ACCESS_COOKIE, User, check_origin, clear_session,
    provider_request, require_user, set_session,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: SecretStr = Field(min_length=1, max_length=1024)


@router.post("/login")
def login(body: LoginRequest, request: Request, response: Response):
    check_origin(request)
    session = provider_request("POST", "token?grant_type=password", payload={
        "email": body.email.strip(), "password": body.password.get_secret_value(),
    })
    return set_session(response, session)


@router.post("/refresh")
def refresh(request: Request, response: Response):
    check_origin(request)
    token = request.cookies.get(REFRESH_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Please sign in.")
    session = provider_request("POST", "token?grant_type=refresh_token", payload={"refresh_token": token})
    return set_session(response, session)


@router.get("/me")
def me(response: Response, user: User = Depends(require_user)):
    response.headers["Cache-Control"] = "no-store"
    return {"id": user.id, "email": user.email}


@router.post("/logout")
def logout(request: Request, response: Response):
    check_origin(request)
    token = request.cookies.get(ACCESS_COOKIE)
    try:
        if token:
            provider_request("POST", "logout?scope=local", token=token)
    except HTTPException:
        # Local cookies must still be cleared if a session has already expired.
        pass
    clear_session(response)
    return {"status": "signed_out"}
