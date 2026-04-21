# lovable-audit

Black-box security scanner for apps built with [Lovable](https://lovable.dev) (or any React + Supabase + Stripe stack).

Paste a URL, get a markdown report listing the security issues your app has before you ship it.

## What it checks

- **Security headers** — CSP, X-Frame-Options, HSTS, etc.
- **CORS** — wildcard origin, reflected origin, credentials leaks
- **Exposed secrets in JS bundles** — OpenAI / Anthropic / Stripe / AWS / Google keys, Supabase `service_role` JWTs
- **TLS/HSTS** — cert validity, HSTS presence and `max-age`
- **DNS hygiene** — SPF + DMARC (only if the domain has mail)

## What it does NOT check

Things that require login, source code, or manual creativity:

- Monetization bypass (client-side limits not enforced server-side)
- Stored XSS, privilege escalation
- Prompt injection on AI endpoints
- Brute-force / rate-limiting
- Row Level Security correctness

These need a real pentest or authenticated testing. The report calls this out explicitly.

## Install

```bash
pipx install git+https://github.com/wojtekwoz/lovable-audit.git
# or for development:
git clone https://github.com/wojtekwoz/lovable-audit
cd lovable-audit
pip install -e .
```

## Use

```bash
lovable-audit https://myapp.lovable.app
```

Options:

- `-o, --output PATH` — where to write the markdown report (default: `./AUDIT_<host>_<date>.md`)
- `--json` — machine-readable JSON to stdout
- `-v, --verbose` — print full evidence to the terminal

Exit codes: `0` clean, `1` at least one HIGH, `2` at least one CRITICAL.

## Tests

```bash
pip install pytest
pytest
```

## Ethics

Only run this against apps you own or have written authorization to test. The scanner is black-box and low-impact (a few GETs, one OPTIONS) but you are responsible for where you point it.

## Roadmap

- [ ] Claude-powered review of JS bundles (insecure patterns, not just secrets)
- [ ] Prompt-injection probes against AI endpoints
- [ ] Authenticated checks (monetization bypass, session handling)
- [ ] Lovable web UI wrapper so non-devs can use it
