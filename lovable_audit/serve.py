"""Entry point: `lovable-audit-serve` — boots the FastAPI backend."""

from __future__ import annotations

import threading
import time
import webbrowser

import click


@click.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Interface to bind.")
@click.option("--port", default=8000, show_default=True, type=int)
@click.option("--reload", is_flag=True, help="Auto-reload on file changes (dev only).")
@click.option("--no-browser", is_flag=True, help="Don't auto-open the UI in your browser.")
def main(host: str, port: int, reload: bool, no_browser: bool) -> None:
    """Run the lovable-audit HTTP backend locally.

    A frontend (e.g. a Lovable-built UI) can POST to http://localhost:<port>/scan
    and consume the SSE stream. CORS is open so preview URLs work out of the box.
    """
    try:
        import uvicorn
    except ImportError as e:
        raise click.ClickException(
            "uvicorn not installed. Run: pip install 'lovable-audit[server]'"
        ) from e

    url = f"http://{host}:{port}"
    click.echo(f"🔒 lovable-audit → {url}")
    click.echo(f"   UI:       {url}/")
    click.echo(f"   API:      POST {url}/scan (SSE)")
    click.echo()

    if not no_browser:
        def _open():
            time.sleep(1.0)
            try:
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

    uvicorn.run(
        "lovable_audit.server:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
