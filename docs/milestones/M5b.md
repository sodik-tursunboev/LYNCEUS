# M5b: Outlook / Microsoft 365 mailbox (read-only)

**Status (2026-11-05): built and tested against a fake Graph, never run against real Microsoft.** Started on your instruction "move next". The M5 plan said Outlook would follow once Gmail was proven; Gmail is not proven live, so this is built the same way: against a fake Graph server, behind the same interface, off by default. Needs you for the live check (an Azure app registration of yours). No new dependency.

**Evidence:** `tests/unit/test_outlook.py` (82 tests, fake in `tests/graphhelp.py`). Mutation check: 23 deliberate breaks of the new safeguards (link host/scheme/path, `@removed`, next-link check, id pattern and URL encoding, size cap, round limit, GET-only guard, 410 mapping, scope allow list, Mail.Read required, tenant check, rotated-token storing, Host check, status merge) were each caught by a failing test; the first run of that check had four survivors, which got their own tests. A clean-baseline run is part of the check script, because an earlier run passed vacuously against a wrong file name.

**Live checklist (yours):** register the app, `connect --provider outlook`, send yourself a harmless test mail, `poll`, confirm status `connected` and one analysed message; remove the app's access and confirm `reauth_needed`; if your account is a work account and consent is refused, that is the administrator-consent question above, not a bug here.

**Goal:** the same product behaviour as Gmail (new mail analysed once, missed mail recovered, read-only, nothing stored but verdicts) for an Outlook.com or Microsoft 365 inbox, through the Microsoft Graph API. **Done when:** the sync, recovery, sign-in and failure handling pass against a fake Graph that follows the documented shapes, the read-only and egress rules are enforced and tested, and the status shows both providers.

## What I found out first (Microsoft documentation, read 2026-11-05)

| Topic | Confirmed | Not stated or not verified |
|---|---|---|
| Changes | `GET https://graph.microsoft.com/v1.0/me/mailFolders/{id}/messages/delta`, per folder. A round ends with `@odata.deltaLink` (keep it for next time); more pages come as `@odata.nextLink`. Tokens are opaque. Deleted items appear with `@removed`. `$filter` allowed only as `receivedDateTime ge/gt <value>` (up to 5,000 messages); `$orderby` only `receivedDateTime desc`; `Prefer: odata.maxpagesize` sets page size | **How long a delta token lasts and the error returned when it is too old are not stated**; I treat HTTP 410 and 404 as "start again from the last N days" |
| Raw message | `GET /me/messages/{id}/$value` returns the message in MIME format | the content type; whether very large messages are cut |
| Permission | delegated `Mail.Read` (and the narrower `Mail.ReadBasic`) exist for personal and work accounts | **whether `Mail.Read` needs administrator consent was not verifiable** (the page was too large to read); `Mail.ReadBasic` cannot return the body |
| Sign-in | authorization code + PKCE (`S256`) at `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/{authorize,token}`; tenants `common`, `organizations`, `consumers` or an id; public clients must not use a secret; `offline_access` is needed for a refresh token; refresh tokens have no fixed lifetime ("relatively long") | the exact lifetime |
| Redirect | for a desktop app use `http://localhost`: the **port is ignored when matching**; `127.0.0.1` needs a manifest edit; `[::1]` is not supported; `http` is allowed only for localhost | |
| Limits | 130,000 requests per 10 seconds per app globally; throttled replies are `429` | the per-mailbox Outlook limits quoted in a summary (10,000 requests per 10 minutes, 4 concurrent) are **unverified**; `Retry-After` for Outlook is not stated; a delta call can fail with `403 ErrorQuotaExceeded` when the mailbox is over quota |

## Decisions (my recommendation is what I build)

| # | Decision | Recommendation |
|---|---|---|
| D1 | Scope | `Mail.Read` + `offline_access` only. After sign-in the granted scopes are checked against an allow list (`Mail.Read`, `offline_access`, `openid`, `profile`, `email`, `User.Read`); **any other scope, above all anything that can write or send, makes Lynceus refuse and store nothing** |
| D2 | Shape | One mail-source interface (position, list recent, changes, raw message); Gmail and Graph both implement it; the sync, recovery, storage and privacy rules are the existing ones, unchanged |
| D3 | Tokens | refresh token DPAPI-encrypted like Gmail's, in its own file; **Microsoft rotates the refresh token on every use, so the new one is stored each time** (a test checks it) |
| D4 | Egress | `graph.microsoft.com` (GET only) and `login.microsoftonline.com`, nothing else; links Graph returns (`nextLink`, `deltaLink`) are refused unless they point at Graph over HTTPS |
| D5 | Your part | an Azure app registration ("Mobile and desktop applications", redirect URI `http://localhost`, delegated `Mail.Read`), its client id in `LYNCEUS_OUTLOOK_CLIENT_ID`, then `python -m core.mailbox connect --provider outlook` |

## Acceptance criteria

1. Same behaviours as Gmail against the fake Graph: first connect reads the last N days once; new mail analysed once; restart and expired token (410/404) recover without repeats; a message deleted before it is fetched is counted; `@removed` entries are ignored; paging; throttling and server errors are stated outcomes; hostile answers are refused.
2. Read-only and egress: only GETs to Graph; only the two hosts; a `nextLink` to anywhere else is refused; a token response with an extra scope is refused and nothing stored; rotated refresh tokens are stored.
3. Privacy: nothing but hashes, rule names and counts stored or logged (planted markers, as for Gmail).
4. Status shows both providers; the agent's notifications work for either.
5. **Not claimed:** that Microsoft accepts this client, that `Mail.Read` works without administrator approval on your account, the delta-token lifetime, or anything about real mailboxes.