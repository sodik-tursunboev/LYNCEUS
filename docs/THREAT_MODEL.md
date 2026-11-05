# Threat model v0

Scope: the MIRAGE system as described in `CLAUDE.md`. Written in M0, before any detection logic exists; it records what we protect, where trust changes, who attacks, and what each top threat will be met with. "Status" says what actually exists today, not what is planned.

## Assets
| Asset | Why it matters |
|---|---|
| Email content and attachments, browsing URLs | private user data; leaving the machine without consent breaks the privacy rule |
| Evidence payloads | may contain the above; the most sensitive stored data |
| OAuth tokens, provider API keys | account takeover or quota theft |
| Verdicts, rules, intel feeds | an attacker who changes a verdict to BENIGN defeats the product |
| Audit log | proof of what was done to user data |
| The host itself | the analysis engine parses hostile files and fetches attacker-chosen URLs |

## Trust boundaries
1. **Untrusted content to parsers.** Everything inside an email, file or page is attacker-controlled.
2. **Core to the network.** URL fetching and provider calls cross here, in both directions.
3. **Browser extension, Native Messaging host, agent, core.** Local IPC chain; each hop must authenticate the previous one.
4. **Core to database.** Local PostgreSQL bound to loopback; holds metadata and encrypted payloads.
5. **Core to third-party providers.** Data egress; only with explicit user authorisation for anything private.
6. **Console to core.** A viewer and restore tool, not trusted to decide anything.

## Attackers
| ID | Who | Can do |
|---|---|---|
| A1 | Phishing author | craft URLs, emails, documents, archives, redirect chains and landing pages |
| A2 | Local malware or process under the same Windows user | talk to local ports and pipes, read user-readable files |
| A3 | Network attacker or compromised intel provider | tamper with, delay or poison provider answers; make providers unavailable |
| A4 | Hostile web page | reach `localhost` services from the browser (DNS rebinding, cross-origin requests) |

## Top threats
| # | Threat | Attacker | Planned mitigation | Status today |
|---|---|---|---|---|
| T1 | **Hostile documents** exploit a parser or exhaust resources (bombs, malformed MIME, polyglots) | A1 | parse only in the sandboxed worker with time/memory/size/archive limits and no network (ADR-008); bomb fixtures generated at test time (M2) | Sandbox built and tested (ADR-008): AppContainer plus Job Object, 29 tests, 7 breakages caught, network and file denial checked by hand. Messages (MIME, headers, HTML) are parsed only inside it (M2a): the host never parses message bytes, treats the worker's reply as hostile (strict typed validation, unknown fields and values rejected), and fails closed when the sandbox is missing or breaks. Bomb shapes (10,000 parts, 2,000-deep nesting, 10 MB line, 3 million tags, 60,000 headers, random bytes) finish inside the limits in the real sandbox. PDFs, images and archives are opened the same way, one attachment per process (M2b): zip and gzip bombs, 12-deep nested archives, a 60,000 x 60,000 pixel PNG header, a 150,000-object PDF, 500 KB of random bytes behind a PDF header and a truncated PNG all finish inside the limits in the real sandbox. The libraries (qpdf, Pillow, OpenCV, lxml, numpy) are native code that has not been audited or fuzzed here. Windows only. |
| T2 | **SSRF**: a crafted URL or redirect makes the engine fetch loopback, private, link-local or cloud-metadata addresses | A1 | resolve and validate every IP at every redirect hop, connect to the validated IP, scheme/port allowlist, redirect and size caps, no credentials (M1) | Guard built and tested (`core/urls/safe_fetch.py`, ADR-011): 19 probe inputs, 40 blocked and 7 allowed addresses, redirect and rebinding cases, fake DNS and transport; 13 weakened versions each fail a test; live run passed. **Off, unwired, no API option.** Nothing else in the codebase may open a socket (a test enforces it). |
| T3 | **Provider poisoning or outage**: a feed says BENIGN for a phishing URL, or a timeout is read as "safe" | A3 | never rely on one provider; timeouts, circuit breakers, provenance and timestamps; failure maps to UNKNOWN/ERROR, never BENIGN (M3) | Enforced and tested (M3): a provider that fails, times out, is paused or was not asked changes neither state nor score and is listed in the verdict; an answer of BENIGN or a malformed reply is an ERROR; a list that is missing or stale is UNAVAILABLE; one provider alone cannot reach MALICIOUS; breaker, limiter, cache and deadline bound the damage of an outage. Provider *poisoning* is only mitigated by needing two independent categories for MALICIOUS: a feed that lies about one URL gets WARN, not BLOCK. Adapters unverified against live services. |
| T4 | **Local IPC spoofing**: a local process or web page injects events or reads verdicts | A2, A4 | authenticated channels, no open unauthenticated ports (ADR-009, M4) | The M1 analysis endpoint needs a bearer token, checks the `Host` header, has no CORS and a rate limit; `/health` is open and says only `ok`. The database port is bound to `127.0.0.1` (verified running). M4: the chain extension → native host → agent → core is built (ADR-009, ADR-016). The browser enforces the host's `allowed_origins` and the host checks the origin again; the pipe is current-user only and a per-install secret is checked in constant time; frames are capped at 64 KiB and every message is strictly validated; unknown types and fields are refused at the host and again at the agent; the agent talks to the core only over loopback (no proxy, no redirect, the resolved address is checked on every connection) with a DPAPI-protected bearer token that reaches the core by environment variable. An override is accepted only from the extension's own warning page and only after the core wrote the audit record. **Residual:** a process running as the same user can read the pipe secret and the token file's owner (DPAPI protects against other users and other machines, not against your own account); web pages can learn that the extension is installed because the warning page is web-accessible (needed for the redirect rule). |
| T5 | **Evidence leakage** through logs, the database, exports or provider calls | A2, A3 | log redaction (done), encrypted payloads (ADR-007), egress only with consent, secret scanning in CI | Redaction implemented and tested against known patterns; evidence encryption not implemented; secret scan active in the commit hook. |
| T6 | **Rule or intel tampering** (a changed rule pack or feed weakens detection) | A2, A3 | rules as reviewed code; signed or pinned feeds; eval regression gate with written reasons | Eval harness and 20 URL rules exist; every rule has fixtures and a verified ATT&CK tag; the ruleset version includes a hash of all rule data. No signing yet. |
| T7 | **Prompt injection** if an LLM ever reads attacker text | A1 | no LLM before M3; an LLM may explain but never decide | No LLM in the system. |
| T8 | **OAuth token theft or scope creep** | A2 | read-only scopes by default, tokens encrypted at rest, scope widening needs approval (M5) | No email access yet. |
| T10 | **The resolver itself**: following a link reveals the user's IP and a visit, burns single-use links, leaks the hostname through DNS, and shows a cloaking site its scanner | A1, A3 | off by default; operator setting only, never per request; honest generic User-Agent; result is one signal and never BENIGN; sandbox or egress boundary from ADR-008 first (ADR-011) | Code exists, disabled and unreachable. ADR-011 is a draft awaiting sign-off. |
| T11 | **Outbound queries reveal what the user looks at**: a provider learns the domains analysed, plus the user's IP and account | A2 | everything off by default; the operator names each provider; only a public registered domain is ever sent, never a URL, path, token, IP or reserved name; message links stay local; list feeds send nothing; every request captured in tests (ADR-015) | Gate and per-provider payloads tested end to end with weakened versions. The residual leak (domain, IP, key owner) is inherent to using RDAP or VirusTotal and is documented. |
| T9 | **Harmful response**: a false positive quarantines legitimate mail or blocks a needed site | A1 (induced) | reversible, idempotent, audited, permission-gated responses; never auto-delete (M6) | `ResponseAction` has no delete; nothing acts yet. |

## What M0 does and does not give
- **Gives:** the safe-failure rule for verdicts (UNKNOWN and ERROR are never safe, enforced in code, tests and the database), log redaction, synthetic-only corpus enforcement, a secret scan on every commit, and the probe data for T2.
- **Does not give:** any real defence against T1, T2, T4 or evidence encryption. Those are listed so nobody mistakes M0 for a secured system.

## Review
Revisit at the end of every milestone. Ownership of the three sign-off ADRs (008, 009, 010) and ADR-007 sits with the project owner.
