# SkeletonKey

> "Unlocking every path, mapping every door."

SkeletonKey is an automated Broken Access Control (IDOR/BOLA) mapping and verification tool. It logs in as multiple roles, crawls the application from each role's perspective, builds an authorization map, captures browser and API traffic, and cross-verifies access using deterministic heuristics plus an optional verifier LLM.

Use SkeletonKey only against applications where you have explicit authorization to test.

## Features

* **AI-driven automated login:** Gemini identifies login fields, handles multi-step authentication flows such as Email -> Next -> Password, and pauses for MFA, security questions, or CAPTCHA when human input is required.
* **Login confidence checks:** The tool validates that a login produced authenticated-state evidence before creating a role session, reducing bad crawls caused by failed or partial logins.
* **Per-user login targets:** A JSON login file can give each user a different login URL, SSO selector, or start target.
* **Concurrent crawling:** Login and crawl phases run across isolated browser contexts with configurable thread counts.
* **Adaptive SPA discovery:** SkeletonKey scores pages for SPA/router/API behavior and automatically runs bounded click discovery when needed. `--spa` forces deeper discovery on every page.
* **Safe interactive discovery:** The crawler opens menus, sidebars, profile/account controls, dropdowns, cards, modals, and other non-destructive controls while avoiding obvious logout, delete, send, and state-changing actions.
* **API harvesting and replay:** XHR/fetch calls are captured during crawl, written to the Excel report, and replayed cross-role during verification. SkeletonKey attempts role-specific Authorization and CSRF token replacement for more reliable API replay.
* **Passive JavaScript recon:** First-party JavaScript is inventoried and Webpack lazy chunks are enumerated, fetched without execution, and analyzed for API candidates. A bounded, non-executing parser reconstructs static template literals, constant maps, and simple Webpack environment exports. Referenced source maps and OpenAPI JSON documents are analyzed within configurable asset and byte budgets.
* **Endpoint provenance:** Runtime requests, DOM routes, forms, bundles, source maps, and API descriptions remain distinguishable instead of being collapsed into one ambiguous endpoint list.
* **Recon safety:** Toggle, mutation-like, and destructive controls are skipped deterministically by default. Synthetic batch clicks require an explicit unsafe opt-in.
* **Coverage accounting:** Reports show advertised/downloaded/parsed assets, candidates by source, state transitions, and skipped risky actions so an incomplete crawl is visible.
* **Evidence redaction:** Persisted traffic redacts cookies, authorization headers, OAuth/SAML material, CSRF values, and other common secrets by default.
* **Authentication flow mapping:** `--authn-map` writes a RAW Mermaid flowchart of login traffic and a conservative CLEAN version that preserves deterministic auth-chain requests while trimming obvious noise.
* **UI authorization mapping:** Visible UI elements are compared across roles and written to the "UI Element Map" sheet.
* **Heuristic and AI verification:** High-risk edit/create/password/report/admin routes are surfaced deterministically. Ambiguous cases can be reviewed by Gemini, OpenAI, or Anthropic with structured verifier metadata.
* **Screenshots:** `--ss` saves sequential full-page screenshots for crawled pages.
* **Map import:** `--import-map` skips crawling and re-verifies a prior `.xlsx` or `.csv` authorization map.
* **Burp proxy support:** Route browser traffic through a proxy with `--proxy`.
* **HTTP Basic Auth and password overlays:** `--password` handles Basic Auth and simple password-gated pages.

## Installation

```bash
git clone https://github.com/armadinsecurity/skeletonkey.py.git
cd skeletonkey.py
pip install -r requirements.txt
playwright install chromium
```

## Configuration

Gemini is used for automated login and auth-flow cleanup, so `google_api_key` is required when using `--logins` or `--authn-map`. Vulnerability verification can use a separate provider.

```json
{
  "google_api_key": "YOUR_GEMINI_KEY",
  "gemini_model": "gemini-3-flash-preview",
  "verify_provider": "openai",
  "openai_api_key": "YOUR_OPENAI_KEY",
  "openai_verify_model": "gpt-5.2",
  "verify_ai_concurrency": 1,
  "verify_ai_delay_ms": 1500
}
```

Set `verify_provider` to `gemini`, `openai`, or `anthropic`. You can override verifier settings per run with `--verify-provider`, `--verify-model`, `--verify-ai-concurrency`, and `--verify-ai-delay-ms`.

## Usage

### Full Audit - Alohomora

Crawl, test, and generate the auth map in one shot:

```bash
python skeletonkey.py --target "https://example.com/login" --logins creds.txt --name MyProject --alohomora
```

### Recon Only - Mockingbird

Crawl, screenshot pages, and generate the auth map, but skip vulnerability testing:

```bash
python skeletonkey.py --target "https://example.com/login" --logins creds.txt --name MyProject --mockingbird
```

For endpoint and coverage recon without forced screenshots or authentication-flow generation:

```bash
python skeletonkey.py --target "https://example.com/login" --logins creds.txt --name MyProject --recon-only
```

### SPA and API Discovery

Adaptive discovery runs automatically when SkeletonKey sees SPA/router/API signals. Use `--spa` only when you want to force deeper discovery on every page:

```bash
python skeletonkey.py --target "https://spa.example.com" --logins creds.txt --name MySPA --spa --alohomora
```

### SSO / Portal Launch

Log into a portal and launch a specific target app:

```bash
python skeletonkey.py --target "https://portal.example.com" --logins creds.txt --name MyApp --sso "text='Launch Dashboard'" --alohomora
```

### Re-Verify an Existing Map

Skip crawling and run verification against a previously saved map:

```bash
python skeletonkey.py --target "https://example.com" --roles roles.json --name MyProject --import-map MyProject/MyProject.xlsx --test
```

### Route Through Burp

```bash
python skeletonkey.py --target "https://example.com/login" --logins creds.txt --name MyProject --proxy http://127.0.0.1:8080 --alohomora
```

### Manual Login Override

Bypass automated login and manually complete authentication in a browser window for complex login flows:

```bash
python skeletonkey.py --target "https://example.com/login" --logins creds.txt --name MyProject --manual-override --mockingbird
```

## Argument Reference

| Flag | Description |
|---|---|
| `--target` | Starting URL. Use the login page when using `--logins`. |
| `--logins` | Path to a `.txt` (`user:pass` per line) or `.json` file for automated login. |
| `--roles` | Path to a `.json` file with pre-baked cookies, headers, or storage. |
| `--name` | Project name used for the output directory and file names. |
| `--alohomora` | Master flag: enables crawl, `--test`, and `--authn-map` when `--logins` is set. |
| `--mockingbird` | Recon mode: crawl, screenshots, and auth map when `--logins` is set. No vulnerability testing. |
| `--recon-only` | Endpoint, asset, UI-state, and coverage reconnaissance without vulnerability verification. |
| `--test` | Run cross-role verification. Can combine with `--import-map`. |
| `--verify-provider` | Override verifier provider: `gemini`, `openai`, or `anthropic`. |
| `--verify-model` | Override verifier model for the selected provider. |
| `--verify-ai-concurrency` | Max concurrent verifier LLM calls. Defaults are conservative by provider. |
| `--verify-ai-delay-ms` | Minimum delay between verifier LLM calls in milliseconds. |
| `--authn-map` | Generate RAW and CLEAN Mermaid auth flowcharts. Requires `--logins`. |
| `--ss` | Save screenshots to `<name>/screenshots/<role>/`. |
| `--import-map` | Path to an existing `.xlsx` or `.csv` map to skip crawling. |
| `--sso` | CSS selector for a portal launch button or pre-login SSO gate. |
| `--proxy` | Proxy URL, for example `http://127.0.0.1:8080`. |
| `--threads` | Concurrent browser instances. Default: `3`. |
| `--spa` | Force SPA discovery. Adaptive JS/SPA detection runs without this flag. |
| `--no-static-js-recon` | Disable passive first-party JavaScript, lazy-chunk, source-map, and referenced-schema discovery. |
| `--no-js-template-resolution` | Disable passive JavaScript template-literal and constant-map reconstruction while retaining the legacy literal scanner. |
| `--recon-max-assets` | Maximum additional assets fetched per role for passive analysis. Default: `150`. |
| `--recon-max-mb` | Maximum retained JavaScript/source-map data per role. Default: `50` MiB. |
| `--validate-static-get` | Actively request read-like static GET/HEAD candidates. Disabled by default because GET is not guaranteed side-effect-free. |
| `--recon-validation-limit` | Maximum static candidates actively validated per role. Default: `100`. |
| `--allow-risky-recon-actions` | Permit AI-approved risky controls and synthetic batch clicks. Unsafe and disabled by default. |
| `--import-traffic` | Import HAR, Burp XML, SkeletonLock traffic JSON, or a METHOD/URL seed file. Repeat the flag for multiple inputs. |
| `--delay` | Page load wait in milliseconds for dynamic rendering. Default: `5000`. |
| `--max-pages` | Max pages to crawl per role. `0` means unlimited. |
| `--spa-max-clicks` | Max click interactions per page. `0` means unlimited with `--spa`; adaptive mode defaults to 45. |
| `--follow-redirects` | Follow external redirects during crawl. |
| `--password` | Password for pages that prompt on each visit, including Basic Auth and HTML overlays. |
| `--username` | Username to pair with `--password`. Required for Basic Auth. |
| `--manual-override` | Skip automated login. Browser opens for manual authentication, then runs crawl in headless mode. |
| `--visible` | Run browsers in visible/headed mode throughout (login and crawl). Useful for debugging. |
| `--ignore` | Comma-separated URL patterns to skip during crawl/verification. |
| `--debug` | Write DEBUG-level logs to `<name>/<name>_DEBUG.log`. |
| `--reasoning` | Log verifier decisions and guardrail reasons during verification. |

## Output

All files are written to `./<name>/`.

| File | Description |
|---|---|
| `<name>.xlsx` | Excel report with authorization map, UI map, API calls, and supporting sheets. |
| `<name>.json` | Evidence for confirmed and suspicious findings. Each finding includes `finding_status` and `confidence`. |
| `<name>_auth_map.html` | RAW Mermaid flowchart of captured login traffic. |
| `<name>_auth_map_CLEAN.html` | Conservative auth-flow cleanup focused on auth, SSO, tokens, redirects, and session-setting requests. |
| `<name>_traffic.json` | Captured traffic when `--mockingbird` is active. |
| `<name>_recon.json` | Provenance-aware endpoint candidates, asset inventory, state transitions, run-to-run diff, and coverage statistics. |
| `screenshots/<role>/` | Full-page PNG screenshots when `--ss` is active. |

### Excel Sheets

* **Authorization Map:** Endpoint x Role matrix. Green means discovered by that role, red means VULNERABLE, orange means SUSPICIOUS / MANUAL CHECK, and blank means not discovered or confirmed.
* **UI Element Map:** Compares visible buttons and interactive elements across roles.
* **API Calls:** Captured XHR/fetch calls by role, including method, path, and status.
* **Recon Candidates:** Runtime and passive candidates with source, role, confidence, resolution type, method source, classification, unresolved expressions, evidence, and observed/validated state.
* **Recon Coverage:** Asset, candidate, and safe-interaction coverage by role.

## How It Works

1. **Login:** Gemini identifies the current login step, fills credentials, handles MFA/CAPTCHA pauses, and SkeletonKey validates login confidence before creating the role.
2. **Crawl:** Each role gets an isolated browser context. The crawler opens navigation controls, extracts links and SPA routes, safely interacts with dynamic UI, screenshots pages when requested, and captures API calls.
3. **Verify:** For endpoints discovered by one role but not another, SkeletonKey directly checks cross-role access. High-risk routes are handled deterministically. Ambiguous cases are sent to the configured verifier with status, final URL, route tags, content type, and body-length metadata.
4. **Report:** SkeletonKey writes the Excel matrix, JSON evidence, auth maps, screenshots, and optional traffic logs.

## Interpreting Results

* `X` means the role discovered the endpoint during normal crawl.
* `VULNERABLE` means a role that did not discover the endpoint was still able to access it during verification, or a high-risk route was deterministically confirmed.
* `SUSPICIOUS` means access looked plausible but was not conclusive. These are included in JSON with `finding_status` and `confidence` for manual review.
* A blank cell means the role did not discover that endpoint during crawl and no verified access was confirmed for that role.
* JSON findings include `finding_status`, `confidence`, affected roles, suspicious roles, and captured request/response evidence.
* Template-resolved candidates are static evidence only. They remain unobserved and unvalidated unless a normal browser request captures them or the operator separately opts into safe GET validation.

## Auth Map Notes

* RAW auth maps show the full captured login traffic after static-resource filtering.
* CLEAN auth maps preserve deterministic must-keep auth-chain requests such as login posts, token exchanges, session-setting responses, SSO redirects, and explicit markers.
* AI cleanup is allowed to remove ambiguity, but obvious auth-chain evidence is preserved and obvious post-auth noise is blocked from being re-added.
* If the CLEAN map looks wrong, compare it to RAW. RAW is the source of truth for what was captured.

## Troubleshooting

* **Login confidence failure:** Re-run with `--visible --debug` and watch the login. The tool refuses low-confidence sessions instead of crawling as a broken role.
* **Missing endpoints:** Review screenshots, use `--visible`, and consider `--spa` or a higher `--spa-max-clicks` for very JS-heavy apps.
* **Too much auth-map noise:** Compare RAW and CLEAN auth maps. CLEAN is conservative, but RAW remains available for inspection.
* **AI rate limits:** Lower `--verify-ai-concurrency` and increase `--verify-ai-delay-ms`. OpenAI defaults are intentionally conservative.
* **API replay false negatives:** Some apps bind CSRF/request tokens to browser state, nonce lifetimes, or one-time request material. SkeletonKey attempts role-specific token replacement, but complex flows may still need manual replay in Burp.
* **Unexpected suspicious count:** Use `--reasoning` to inspect verifier decisions and guardrail reasons.
* **Crawl loops or repeated UI clicks:** Set `--spa-max-clicks` to cap per-page interaction and inspect debug logs.

## Login File Formats

Plain text:

```text
admin@example.com:password1
staff@example.com:password2
```

JSON:

```json
[
  {
    "username": "admin@example.com",
    "password": "password1",
    "target": "https://example.com/admin/login"
  },
  {
    "username": "staff@example.com",
    "password": "password2",
    "target": "https://example.com/login",
    "sso": "text='Sign in with SSO'"
  }
]
```

Use JSON when roles have different login URLs, SSO launch selectors, or start targets.

## Notes

* `--mockingbird` is useful for recon when you want screenshots, endpoint mapping, API capture, and auth maps before running active verification.
* `--spa` is no longer required for normal SPA support. It is a force-on override for difficult apps.
* When using `--sso`, make sure the selector uniquely identifies the intended launcher or pre-login gate.
* CAPTCHA handling pauses execution. Solve the CAPTCHA in the browser, submit if needed, then press Enter in the terminal.
