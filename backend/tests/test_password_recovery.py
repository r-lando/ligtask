import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app.main import app
from app.api import recovery

ORIGIN = {'Origin': 'http://127.0.0.1:5173'}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv('AUTH_ALLOWED_ORIGINS', ORIGIN['Origin'])
    monkeypatch.setenv('AUTH_ALLOWED_EMAILS', 'alice@example.com')
    monkeypatch.delenv('AUTH_RECOVERY_REDIRECT_URL', raising=False)
    return TestClient(app)


def test_recovery_uses_fixed_redirect_and_generic_response(client, monkeypatch):
    calls = []
    monkeypatch.setattr(recovery, 'provider_request', lambda *a, **kw: calls.append((a, kw)) or {})
    good = client.post('/auth/password-recovery', headers=ORIGIN, json={'email': 'alice@example.com'})
    unknown = client.post('/auth/password-recovery', headers=ORIGIN, json={'email': 'unknown@example.com'})
    assert good.status_code == unknown.status_code == 200
    assert good.json() == unknown.json()
    assert len(calls) == 1
    assert calls[0][0][1] == 'recover?redirect_to=http%3A%2F%2F127.0.0.1%3A5173%2Freset-password'


def test_reset_rejects_invalid_token_before_update(client, monkeypatch):
    calls = []
    def provider(method, path, **kw):
        calls.append(method)
        raise HTTPException(401, 'Expired recovery session.')
    monkeypatch.setattr(recovery, 'provider_request', provider)
    response = client.post('/auth/reset-password', headers=ORIGIN, json={'access_token': 'invalid', 'password': 'new-test-password'})
    assert response.status_code == 401
    assert calls == ['GET']


def test_reset_verifies_owner_and_updates_with_same_token(client, monkeypatch):
    calls = []
    def provider(method, path, **kw):
        calls.append((method, path, kw))
        return {'id': '11111111-1111-4111-8111-111111111111', 'email': 'alice@example.com', 'email_confirmed_at': '2026-01-01'}
    monkeypatch.setattr(recovery, 'provider_request', provider)
    response = client.post('/auth/reset-password', headers=ORIGIN, json={'access_token': 'test-token', 'password': 'new-test-password'})
    assert response.status_code == 200
    assert [call[0] for call in calls] == ['GET', 'PUT']
    assert all(call[2]['token'] == 'test-token' for call in calls)
    assert 'test-token' not in response.text
    assert 'HttpOnly' not in response.headers.get('set-cookie', '') or 'Max-Age=0' in response.headers['set-cookie']


def test_reset_rejects_disallowed_account(client, monkeypatch):
    calls = []
    def provider(method, path, **kw):
        calls.append(method)
        return {'id': '11111111-1111-4111-8111-111111111111', 'email': 'outside@example.com', 'email_confirmed_at': '2026-01-01'}
    monkeypatch.setattr(recovery, 'provider_request', provider)
    assert client.post('/auth/reset-password', headers=ORIGIN, json={'access_token': 'token', 'password': 'new-test-password'}).status_code == 403
    assert calls == ['GET']


def test_recovery_rejects_foreign_origin_and_short_password(client, monkeypatch):
    monkeypatch.setattr(recovery, 'provider_request', lambda *a, **kw: pytest.fail('Provider should not be called'))
    assert client.post('/auth/password-recovery', headers={'Origin': 'https://evil.invalid'}, json={'email': 'alice@example.com'}).status_code == 403
    assert client.post('/auth/reset-password', headers=ORIGIN, json={'access_token': 'token', 'password': 'short'}).status_code == 422


def test_recovery_rejects_untrusted_redirect(client, monkeypatch):
    monkeypatch.setenv('AUTH_RECOVERY_REDIRECT_URL', 'https://evil.invalid/reset-password')
    monkeypatch.setattr(recovery, 'provider_request', lambda *a, **kw: pytest.fail('Provider should not be called'))
    assert client.post('/auth/password-recovery', headers=ORIGIN, json={'email': 'alice@example.com'}).status_code == 503
