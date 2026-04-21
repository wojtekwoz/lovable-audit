"""Unit tests for secret detection.

Fixtures are constructed at runtime from harmless parts so this file contains
no raw patterns that secret scanners would flag.
"""

from lovable_audit.checks.secrets import _scan_text


def _fake_openai() -> str:
    return "sk-" + "proj" + "1234567890abcdefghijklmnop"


def _fake_anthropic() -> str:
    return "sk-ant-" + "api03-" + "abcdefghijklmnopqrstuvwxyz0123456789"


def _fake_stripe_live() -> str:
    return "sk_" + "live_" + "abcdefghijklmnopqrstuvwxyz"


def _fake_aws() -> str:
    return "AKIA" + "IOSFODNN7EXAMPLE"


def _fake_google() -> str:
    return "AIza" + "SyAbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


def _fake_service_role_jwt() -> str:
    # header={"alg":"HS256"} payload={"role":"service_role","iss":"supabase"}
    return (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UifQ."
        "signaturehere"
    )


def _build_fixture() -> str:
    return "\n".join(
        f'const x{i} = "{v}";'
        for i, v in enumerate(
            [
                _fake_openai(),
                _fake_anthropic(),
                _fake_stripe_live(),
                _fake_aws(),
                _fake_google(),
                _fake_service_role_jwt(),
            ]
        )
    )


def test_detects_all_synthetic_keys():
    findings = _scan_text(_build_fixture(), "bundle.js")
    titles = {f.title for f in findings}

    assert any("OpenAI" in t for t in titles)
    assert any("Anthropic" in t for t in titles)
    assert any("Stripe live" in t for t in titles)
    assert any("AWS" in t for t in titles)
    assert any("Google" in t for t in titles)
    assert any("service_role" in t for t in titles)


def test_anon_jwt_not_flagged_as_service_role():
    # payload={"role":"anon"}
    anon = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig"
    findings = _scan_text(f'const a = "{anon}";', "x")
    assert not any("service_role" in f.title for f in findings)


def test_clean_text_has_no_findings():
    findings = _scan_text("const greeting = 'hello world';", "clean.js")
    assert findings == []
