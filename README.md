# JS Strike

> **JavaScript Static Analysis CLI for Authorized Security Testing & Bug Bounty Recon**

JS Strike (`jsstrike`) is a modular Python CLI tool that performs static analysis on a target website's JavaScript to identify client-side security flaws, leaked secrets, hidden backend attack surface, and vulnerable dependencies — all without live exploitation.

⚠️ **For authorized security testing and bug bounty programs only.** Never use against targets without explicit permission.

## Features

### Client-Side Execution Flaws
- **DOM-based XSS** — detects sources (`location.hash`, `document.URL`, `postMessage data`, etc.) flowing into sinks (`innerHTML`, `eval()`, `document.write()`, jQuery `.html()`, etc.) with proximity-based confidence scoring
- **Insecure postMessage handlers** — flags `addEventListener("message", ...)` listeners missing `event.origin` checks
- **DOM-based open redirects** — URL-controlled values flowing into `location.href`, `location.assign()`, `window.open()` without domain allowlisting
- **Client-side prototype pollution** — recursive merge/clone/extend functions that don't filter `__proto__`/`constructor`/`prototype` keys
- **Sensitive data in browser storage** — `localStorage`/`sessionStorage` calls storing values that look like JWTs, tokens, or PII

### Sensitive Information & Secret Exposure
- **Regex secret scanner** — AWS keys, Firebase configs, Stripe keys, Slack webhooks, GitHub tokens, generic API key patterns, DB connection strings, JWTs, hardcoded passwords, private keys
- **Internal infra leakage** — internal hostnames, staging/dev URLs, S3 bucket names, developer emails, CI/CD metadata, cloud metadata endpoints
- **Exposed source maps** — flags `//# sourceMappingURL=` references; fetches and reports reconstructed source file structure

### Hidden Backend Attack Surface
- **Endpoint extraction** (LinkFinder-style) — regex-extracts paths/routes from JS strings, especially `/api/`, `/admin/`, `/v1/`, `/v2/` patterns
- **Admin/internal route flagging** — routes containing `admin`, `internal`, `debug`, `swagger`, `graphql`
- **IDOR/BAC candidates** — routes with ID-like parameters (`/user/{id}`, `/order/:id`)
- **Client-side-only validation** — flags logic blocks computing price/role/permission checks purely in JS

### Supply Chain & Dependency Flaws
- **Library fingerprinting** — identifies jQuery, Angular, React, Vue, Lodash, Bootstrap, Moment.js, and 15+ other libraries with version extraction
- **CVE cross-reference** — checks detected versions against a local, extensible vulnerability lookup table
- **EOL/outdated flagging** — flags libraries past their end-of-life even without a specific CVE

## Installation

```bash
pip install -r requirements.txt
# or
pip install -e .
```

## Usage

```bash
# Basic scan
python -m jsstrike http://target.com

# JSON output
python -m jsstrike http://target.com --json > report.json

# Include third-party scripts
python -m jsstrike http://target.com --include-third-party

# Add extra allowed domains
python -m jsstrike http://target.com --allow-domain cdn.target.com --allow-domain assets.target.com

# Run only specific detectors
python -m jsstrike http://target.com --only-xss
python -m jsstrike http://target.com --only-secrets
python -m jsstrike http://target.com --only-endpoints

# Skip specific detectors
python -m jsstrike http://target.com --skip-libraries --skip-infra

# Filter by minimum severity
python -m jsstrike http://target.com --min-severity medium

# Verbose output (snippets for all severities)
python -m jsstrike http://target.com --verbose
```

## Testing with Bundled Fixtures

```bash
# Terminal 1: start the fixture server
python serve_fixtures.py

# Terminal 2: run jsstrike against it
python -m jsstrike http://127.0.0.1:8777

# Or JSON output
python -m jsstrike http://127.0.0.1:8777 --json | python -m json.tool
```

## Output

Each finding includes:
- **File URL** — which script file
- **Line number** — where in the file
- **Category** — what class of vulnerability
- **Snippet** — the matched code context
- **Explanation** — one-line description
- **Confidence** — low / medium / high
- **Severity** — info / low / medium / high / critical

The terminal report is color-coded by severity and includes summary sections for extracted endpoints and detected secrets.

## Architecture

```
jsstrike/
├── __init__.py          # Package init
├── __main__.py          # python -m jsstrike entry
├── main.py              # CLI argparse and orchestration
├── models.py            # Finding dataclass, enums
├── fetcher.py           # HTML fetch, script extraction, JS download, source maps
├── xss.py               # DOM XSS, postMessage, open redirect, prototype pollution, storage
├── secrets.py           # Secret scanner, internal infrastructure leakage
├── endpoints.py         # Endpoint extraction, admin routes, IDOR, client-side validation
├── libraries.py         # Library fingerprinting, CVE lookup, EOL detection
└── report.py            # Terminal and JSON report output
```

## License

MIT
