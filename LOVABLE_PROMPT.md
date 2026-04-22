# Lovable Prompt — lovable-audit UI

Paste this prompt into [lovable.dev](https://lovable.dev) to generate the frontend.

---

## Prompt

Build a single-page web app called **"lovable-audit"** — a security scanner UI. It calls a local Python backend and displays live results.

### Design

- Dark mode, minimal, developer-tool aesthetic (think: Linear, Raycast, Vercel dashboard).
- Main color accent: emerald green for success, amber for medium severity, red for critical/high.
- Use `shadcn/ui` components (Button, Input, Card, Badge, Collapsible, Checkbox, Switch, Label).
- Monospace font for URLs, evidence, and code snippets.

### Layout

**Header:** logo/title "lovable-audit" + tagline "Black-box security scan for apps built with Lovable" + link "GitHub →" pointing to https://github.com/wojtekwoz/lovable-audit.

**Main form (card, centered, max-width 640px):**

1. **URL input** (required) — placeholder `https://yourapp.com`, full width.
2. **Advanced options** (collapsible, closed by default):
   - `Credentials` text input — placeholder `email:password`, helper text: "test account for auth-required checks"
   - `Supabase anon key` text input (optional) — helper text: "override if auto-detection fails"
   - `Aggressive mode` toggle — helper text: "enables destructive checks: brute-force login, stored XSS probing. Only use on apps you own."
3. **"Run scan" button** — emerald, full width, large. Disabled while scan is running, shows spinner.

### Live results area (appears after clicking Run scan)

**Two-column layout:**

**Left column — Checklist:**
Each check is a row with:
- Icon: `⋯` (pending), `🔍` (running), `✓` (green, clean), `✗` (colored by severity), `—` (skipped, gray)
- Check name (e.g. "Security headers", "RLS probing")
- Badge: finding count by severity (e.g. "1 HIGH, 2 MEDIUM") OR "skipped" with reason on hover.

Checks to display in this order:
1. Security headers
2. CORS configuration
3. Exposed secrets
4. TLS/HSTS
5. DNS hygiene
6. Claude review
7. RLS probing
8. Brute-force rate limit
9. Prompt injection
10. Privilege escalation
11. Monetization bypass
12. Stored XSS

**Right column — Report preview:**
- While scan runs: live summary counter ("1 HIGH found so far…")
- When done: rendered markdown report inside a scrollable card, with a "Download .md" button at the top.

### Backend communication

**Endpoint:** `POST http://localhost:8000/scan`

**Request body:**
```json
{
  "url": "https://example.com",
  "credentials": "email:password",   // optional, omit if empty
  "supabase_key": "eyJ...",          // optional
  "aggressive": false,
  "skip": []                          // array of check names
}
```

**Response:** `text/event-stream` (Server-Sent Events). Each event is a JSON object, one of:

1. **Per-check update:**
   ```json
   {
     "type": "check",
     "name": "Security headers",
     "skipped": false,
     "skip_reason": null,
     "error": null,
     "findings": [
       {"id":"HDR-01","severity":"HIGH","title":"...","evidence":"...","recommendation":"...","cvss":6.1,"source":"passive"}
     ]
   }
   ```

2. **Final report:**
   ```json
   {
     "type": "report",
     "url": "https://example.com",
     "date": "2026-04-22",
     "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3},
     "markdown": "# Raport Audytu..."
   }
   ```

3. **Error (rare):**
   ```json
   {"type": "error", "message": "..."}
   ```

Parse SSE using the native `EventSource` API or `fetch` + `ReadableStream` + manual line splitting on `data: `.

### Behavior details

- Before showing the form: do a health check — `GET http://localhost:8000/healthz`. If it fails, show a banner: "Backend not running. Start it with `lovable-audit-serve` in your terminal."
- Render the final markdown using `react-markdown` with `remark-gfm` plugin (for tables).
- Download button: create a Blob from the markdown, trigger download as `AUDIT_<host>_<date>.md`.
- Show a toast when scan completes: "Scan complete — X findings".

### Empty/error states

- **No URL entered:** button disabled
- **Invalid URL:** inline error under the input
- **Backend unreachable:** full-page banner with CLI instructions
- **Scan error from backend:** red banner inside the results area, but keep any check-level findings collected so far

### Out of scope for v1

- Saving history of past scans (localStorage maybe later)
- User accounts / auth on the UI itself (local tool, no auth needed)
- Editing/cleaning up XSS canary rows (cleanup SQL is in the report — user handles it)

---

## After Lovable generates it

1. Click "Preview" in Lovable — the UI will try to reach `http://localhost:8000/healthz`
2. In a separate terminal, run: `lovable-audit-serve`
3. Preview should switch from "backend not running" to the form
4. Paste a URL and click "Run scan"

If CORS blocks the request from the Lovable preview domain: the backend already sets `Access-Control-Allow-Origin: *` so this should just work.
