"""Email recovery without exposing provider tokens in local storage or logs."""
import os
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field, SecretStr
from app.services.auth_service import check_origin, clear_session, provider_request, user_from_data, allowed_origins

router = APIRouter(prefix='/auth', tags=['Authentication'])


class RecoveryRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)


class PasswordReset(BaseModel):
    access_token: SecretStr = Field(min_length=1, max_length=8192)
    password: SecretStr = Field(min_length=12, max_length=1024)


@router.post('/password-recovery')
def request_recovery(body: RecoveryRequest, request: Request, response: Response):
    check_origin(request)
    redirect = os.getenv('AUTH_RECOVERY_REDIRECT_URL', 'http://127.0.0.1:5173/reset-password')
    parsed = urlparse(redirect)
    if parsed.fragment or parsed.query or parsed.username or parsed.password or f'{parsed.scheme}://{parsed.netloc}' not in allowed_origins():
        raise HTTPException(status_code=503, detail='Password recovery is not configured correctly.')
    email = body.email.strip().lower()
    allowed = {value.strip().lower() for value in os.getenv('AUTH_ALLOWED_EMAILS', '').split(',') if value.strip()}
    if email in allowed:
        provider_request('POST', 'recover?' + urlencode({'redirect_to': redirect}), payload={'email': email})
    response.headers['Cache-Control'] = 'no-store'
    return {'message': 'If this email has access, a password-reset link will arrive shortly. Open only the newest email.'}


@router.post('/reset-password')
def reset_password(body: PasswordReset, request: Request, response: Response):
    check_origin(request)
    token = body.access_token.get_secret_value()
    # Provider verification and the normal confirmed-email allowlist apply here too.
    user_from_data(provider_request('GET', 'user', token=token))
    provider_request('PUT', 'user', token=token, payload={'password': body.password.get_secret_value()})
    clear_session(response)
    return {'message': 'Password updated. Sign in with your new password.'}
