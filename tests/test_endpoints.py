"""Offline tests for active/endpoints.py — endpoint discovery + classification."""

from lovable_audit.active.endpoints import _classify, discover_endpoints
from lovable_audit.models import ScanContext


def test_classify_ai():
    assert _classify("https://app.com/api/chat") == "ai"
    assert _classify("https://app.com/api/generate") == "ai"
    assert _classify("https://api.openai.com/v1/chat/completions") == "ai"


def test_classify_auth():
    assert _classify("https://x.supabase.co/auth/v1/token") == "auth"
    assert _classify("https://app.com/api/login") == "auth"


def test_classify_rest_and_api():
    assert _classify("https://x.supabase.co/rest/v1/profiles") == "rest"
    assert _classify("https://app.com/api/v1/users") == "api"


def test_discover_from_bundle():
    ctx = ScanContext(url="https://app.com")
    bundle_text = """
        const data = await fetch("https://app.com/api/chat", {method: "POST"});
        axios.get("/api/users");
        const url = "/rest/v1/profiles";
        fetch(`/api/generate`);
    """
    ctx.js_bundles = [("main.js", bundle_text)]
    discover_endpoints(ctx)
    kinds = {e["kind"] for e in ctx.discovered_endpoints}
    urls = {e["url"] for e in ctx.discovered_endpoints}
    assert "ai" in kinds
    assert any("chat" in u for u in urls)
    assert any("rest/v1/profiles" in u for u in urls)


def test_dedup():
    ctx = ScanContext(url="https://app.com")
    ctx.js_bundles = [
        ("a.js", 'fetch("/api/chat")'),
        ("b.js", 'fetch("/api/chat")'),
    ]
    discover_endpoints(ctx)
    chat_urls = [e for e in ctx.discovered_endpoints if "chat" in e["url"]]
    assert len(chat_urls) == 1
