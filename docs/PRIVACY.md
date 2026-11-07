# Privacy: what is stored, where, and what leaves the machine

Written from the code (database models, the agent's file formats, the log statements), not from memory. Lynceus is local-first: by default **nothing leaves this computer**.

## What leaves the machine

| What | When | Where to |
|---|---|---|
| Nothing | by default | |
| A bare registered domain (no path, query, user name, port or IP) or a hash | only for a threat-intelligence provider **you name** in `LYNCEUS_INTEL_PROVIDERS`: RDAP and VirusTotal get one public domain; list feeds (PhishTank, OpenPhish, URLhaus) are *downloaded* and matched here, so nothing about your URL is sent | that provider. Links inside email only reach list feeds unless `LYNCEUS_INTEL_EMAIL_LINKS=true`. See ADR-015 |
| Requests to read your mail | only after you connect Gmail | `gmail.googleapis.com`, `oauth2.googleapis.com`, `accounts.google.com`, read-only, GET only (enforced in code) |
| Requests to read your mail | only after you connect Outlook | `graph.microsoft.com` (GET only, enforced in code), `login.microsoftonline.com` (sign-in and token refresh), read-only `Mail.Read` |
| Requests that move a message in your mail | only after you give the **separate write permission** (`connect --write`) **and** click Approve on a MALICIOUS message | the same hosts as above. Gmail: list or create the label `LYNCEUS-Quarantine`, change one message's labels. Outlook: list or create the folder `Lynceus Quarantine`, read one message's folder, move it. Nothing else (no delete, send, draft, trash: refused in code before sending). The message id goes to the provider, because that is how the message is named |
| A Windows toast, a browser warning page | always, but local | your screen |

The agent talks to the core only over loopback (no proxy, no redirects, the resolved address is checked on every connection). The extension makes no network requests of its own.

## What is stored in the database (PostgreSQL)

Hashes, hosts, states, scores, rule names and counts. **Never**: a URL, a file name or path, a message body, subject or address, an attachment, a token.

| Table | Holds |
|---|---|
| `events`, `artifacts` | when and from which source (browser, agent, email, API); kind; SHA-256 of the URL/file/message; the host (at most 253 characters) |
| `domains`, `extracted_urls` | host names seen, SHA-256 of each extracted link (the link text itself is NULL) |
| `verdicts`, `detections`, `evidence`, `provider_results` | the state, score, confidence, recommended and applied response; the rules that fired with their description; redacted evidence summaries (hosts, types, counts); what each provider said, when, and its provenance |
| `actions`, `allowlist` | a response's state, the agent's opaque file id, the file's SHA-256, who decided, a reason code, times; allow-listed hashes with expiry. For an email action also the provider (`gmail` or `outlook`) and **the provider's message id (`mail_ref`)**, the one place a message id is kept in the clear: it is needed to find the message again, never returned by the API, never written to the audit log or any log, and cleared when the action is restored (a test plants an id and searches the API output, audit log, logs and every other column) |
| `audit_logs` | who did what and when: action names, states, hash prefixes (12 characters); for a "continue anyway" override the host and a hash of the URL, never the URL |

There is no encryption of the database (ADR-007 is unsigned) because nothing in it is content. There is no automatic deletion: it grows until you clear it.

## What is stored on disk by the agent (`%LOCALAPPDATA%\Lynceus`, current user only)

These are the places where **local** names and paths do exist, because the agent needs them to find and move your files. They are never sent to the core or logged.

| File | Holds | Sensitive because |
|---|---|---|
| `spool.jsonl` | the full path of each file waiting to be judged (and its size and time) | paths contain your user name and folder names |
| `flagged.json` | for files judged MALICIOUS: path, hash, size, time, which notifications were shown | same |
| `quarantine\<id>\record.json` | the original path, hash, attributes, and **the file's Mark of the Web text, which contains the full download and referrer URLs** | the URLs can carry tokens |
| `quarantine\<id>\payload.quar` | the quarantined file itself (not encrypted, not defanged) | it is the dangerous file |
| `state.json` | the file watcher's checkpoint time | |
| `agent.log`, `core.log` | counts, short ids of files (a hash of the path), states, error types; no URL, file name or path is written on purpose (tests search the agent's log and the mailbox logs for planted markers; `core.log` is the core's redacting log plus the web server's start-up lines) | |
| `core.token` | the API token, encrypted with Windows DPAPI for your user | other users and other machines cannot read it |
| `pipe.secret` | the password the native host uses to talk to the agent, plain text | any program running as you can read it (same trust level as anything you run) |

The core's own folder (`.data/`) holds downloaded list feeds and, if Gmail is connected, `mailbox\gmail.token` (DPAPI-encrypted refresh token) and `gmail-state.json` (a history position, SHA-256 of message ids already analysed, retry counts; no address, subject or body). Outlook has its own pair, `outlook.token` and `outlook-state.json`, with the same contents (the position is Microsoft's opaque change link). If you gave the email-quarantine permission there is a third file per provider, `gmail-write.token` / `outlook-write.token` (DPAPI-encrypted refresh token for the wider permission; the reading poller never uses it).

## In the browser extension

The verdict cache lives in `chrome.storage.session` (memory, gone when the browser closes), keyed by a hash of the exact URL, holding a state, a score and rule descriptions. The warning page receives the URL in its own address so it can show it to you; it is not sent anywhere. The "continue anyway" decision goes to the agent, which has the core write the audit row (host and URL hash only).

## Keys and secrets

`.env` holds `LYNCEUS_API_TOKEN`, provider keys and the database URL **in plain text** (owner decision): keep it out of backups you share and out of git (it is ignored; a secret scan runs on every commit). Provider keys, tokens and the Gmail refresh token are `SecretStr` or encrypted and are never written to logs, the database or results. A test per component plants markers and searches the stored data and logs for them.

## What you control

Turn providers and Gmail off by leaving their settings empty; `python -m core.mailbox disconnect` revokes Google's access and deletes the tokens (`--provider outlook` deletes the local tokens and state; remove the app in your Microsoft account's app-permissions page to end its access); `disconnect --write` withdraws only the wider email-quarantine permission; `deploy\uninstall.ps1 -RemoveData` deletes the data folder (including the quarantine); clearing the database tables removes the history.