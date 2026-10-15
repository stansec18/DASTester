# DASTester

**DASTester** is a dynamic application security testing (DAST) scanner. It
performs runtime security checks against HTTP/HTTPS web applications,
categorises every finding against the **OWASP Top 10 (2021)**, maps it onto
the **STRIDE** threat model, and produces clean **HTML and PDF** reports.

> ⚠️ **Authorised testing only.** DASTester sends live requests to the target.
> Only scan systems you own or have explicit, written permission to test.
> Unauthorised scanning may be illegal.

---

## Features

- **Scope-bounded crawler** — discovers pages, parameters, and forms, and never
  sends a request outside the configured scope.
- **21 checks** across three tiers (passive / active / aggressive).
- **OWASP Top 10 (2021) + STRIDE** classification on every finding.
- **HTML + PDF + JSON** reports.
- **Self-update** with `dastester --update`.
- **Rate limiting**, custom headers/cookies, authenticated scans, CI-friendly
  exit codes.

### Coverage

**Passive** (always run, no requests beyond the crawl):

| Area | Check |
|---|---|
| Security headers | HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy |
| Transport / TLS | plaintext HTTP, deprecated TLS, cert expiry & validation |
| Cookies | Secure / HttpOnly / SameSite |
| CSRF | state-changing forms without anti-CSRF tokens |
| JWT / tokens | `alg:none`, missing `exp`, weak HMAC secret (offline) |
| Session handling | session IDs in URLs, over-long persistent sessions |
| Info disclosure | version banners, verbose errors / stack traces |
| Content security | mixed content, weak CSP directives |

**Active** (require `-I/--i-am-authorized`; non-destructive by design):

| Area | Check |
|---|---|
| XSS — reflected | unencoded reflection of an inert marker |
| XSS — stored | inject-then-recrawl correlation across pages |
| SQLi — error | baseline-aware single-quote probe |
| SQLi — blind | boolean- and time-based (bounded delay) |
| Open redirect | off-scope canary, redirect never followed |
| CORS | reflected/`*`/`null` origin with credentials |
| SSRF (surface) | URL-fetch params → off-scope canary signals |
| HTTP methods | PUT / DELETE / TRACE / CONNECT via OPTIONS |
| Exposure | directory listing, `.git`/`.env`/backup/config files |
| `well-known` | missing security.txt, sensitive robots.txt paths |
| Access control | IDOR/BOLA/BFLA **differential** (needs 2-session config) |

**Aggressive** (require `-I` **and** `--aggressive`; may disrupt live traffic):

| Area | Check |
|---|---|
| Request smuggling | CL.TE timing desync (detection only, no victim request) |
| SSRF (internal) | probes cloud-metadata / loopback via URL-fetch params |

### What is intentionally *not* fully automatic

- **DOM-based XSS** needs a JavaScript engine (headless browser) — not covered
  by this HTTP-only build. Planned as an optional Playwright engine.
- **Blind SSRF / blind XSS** need an out-of-band (OAST) listener you host;
  DASTester reports the surface and recommends OAST confirmation.
- **IDOR / BOLA / BFLA** cannot be judged from a single session. The
  `access-control` check runs a safe cross-account differential **when you
  supply two sessions + an endpoint list** (see
  `dastester/checks/aggressive/access_control.py`); otherwise it reports that it
  needs configuration rather than guessing object IDs blindly.

---

## Installation

```bash
git clone https://github.com/stansec18/dastester.git
cd dastester
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# optional: install the `dastester` command
pip install -e .
```

> **PDF note:** PDF export uses [WeasyPrint](https://weasyprint.org/) and falls
> back to `xhtml2pdf` automatically. WeasyPrint needs a few system libraries
> (`libpango`, `libcairo`, `libgdk-pixbuf`). On Debian/Ubuntu:
> `sudo apt-get install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0`.
> If neither engine is available, the HTML report is still produced.

---

## Usage

```bash
# Passive-only scan (safe default when authorisation is not asserted)
python dastester.py https://example.com

# Full active scan (you confirm you are authorised)
python dastester.py https://example.com --i-am-authorized

# Include high-risk checks (request smuggling, internal SSRF) — explicit opt-in
python dastester.py https://example.com -I --aggressive

# Tune crawl + politeness, add auth, choose formats
python dastester.py https://app.example.com -I \
    --depth 3 --max-pages 300 --rate 3 \
    --include-subdomains \
    --header "Authorization: Bearer <token>" \
    --cookie "session=abc123" \
    -o reports -n app-example -f html,pdf,json
```

Reports are written to `./reports/` by default.

### Common options

| Option | Description |
|---|---|
| `-I, --i-am-authorized` | Confirm authorisation; enables active checks. |
| `--aggressive` | Enable high-risk checks (request smuggling, internal SSRF). Requires `-I`. |
| `--passive-only` | Only passive checks (no probing requests). |
| `--depth N` | Max crawl depth (default 2). |
| `--max-pages N` | Max pages to crawl (default 200). |
| `--include-subdomains` | Treat subdomains as in scope. |
| `--scope HOST` | Add an in-scope host (repeatable). |
| `--rate R` | Max requests/second (default 5). |
| `--header K:V` / `--cookie K=V` | Auth and custom values (repeatable). |
| `--insecure` | Don't verify TLS (issues still reported). |
| `-f, --format` | `html,pdf,json` (default `html,pdf`). |

**Exit codes:** `0` = no High/Critical findings, `2` = High or Critical present
(handy for CI gates).

---

## Updating

```bash
dastester --update       # or: python dastester.py --update
```

- If installed from a **git clone**, DASTester runs `git pull --ff-only`.
- Otherwise it upgrades via `pip install --upgrade git+<repo>`.

Point updates at your own fork by editing `DEFAULT_REPO` in
`dastester/core/updater.py`, or by setting the `DASTESTER_REPO` environment
variable (and optionally `DASTESTER_BRANCH`).

---

## How detection stays non-destructive

DASTester's active checks are **detection-oriented**: they establish a baseline,
send a small number of **inert** probes (a unique marker, a single syntax
character, an off-scope canary), and infer unsafe handling from the server's
*own* response. No payload is designed to execute, extract, modify, or damage
data, and a global rate limiter plus hard scope enforcement keep the scan
polite and contained. Always validate findings manually before acting on them.

---

## Project layout

```
dastester/
├── dastester.py              # no-install entry point
├── requirements.txt
├── setup.py
└── dastester/
    ├── cli.py               # argparse CLI, --update
    ├── core/                # config, http client, crawler, scanner, updater
    ├── checks/              # passive/ active/ aggressive/ check modules
    ├── models/              # Finding, OWASP, STRIDE reference data
    └── reporting/           # HTML/PDF/JSON renderers + template
```

Add a check by subclassing `BaseCheck` in `dastester/checks/{passive,active,
aggressive}` and importing it in `dastester/checks/__init__.py`; it
auto-registers. Set `kind` to `PASSIVE`, `ACTIVE`, or `AGGRESSIVE`.

## License

MIT — see [LICENSE](LICENSE).
