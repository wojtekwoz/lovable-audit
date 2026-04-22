"""Offline tests for active/discovery.py — Supabase URL + anon key extraction."""

import base64
import json

from lovable_audit.active.discovery import SUPABASE_URL_RE, _is_anon_jwt


def _make_jwt(role: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload_json = json.dumps({"role": role, "iss": "supabase"}).encode()
    payload = base64.urlsafe_b64encode(payload_json).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


def test_supabase_url_regex():
    text = 'const url = "https://qqacdhbxjduiacmwfhxf.supabase.co/rest/v1/foo";'
    m = SUPABASE_URL_RE.search(text)
    assert m is not None
    assert m.group(0) == "https://qqacdhbxjduiacmwfhxf.supabase.co"


def test_anon_jwt_detected():
    anon = _make_jwt("anon")
    assert _is_anon_jwt(anon) is True


def test_service_role_not_anon():
    service = _make_jwt("service_role")
    assert _is_anon_jwt(service) is False


def test_authenticated_not_anon():
    auth = _make_jwt("authenticated")
    assert _is_anon_jwt(auth) is False


def test_broken_jwt_returns_false():
    assert _is_anon_jwt("not.a.jwt") is False
    assert _is_anon_jwt("also-not-a-jwt") is False
