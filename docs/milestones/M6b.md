# M6b: Email quarantine (Gmail and Outlook), reversible

**Status (2026-11-06): built, not run against real Google or Microsoft.** Done: the narrow request guard and the Gmail and Outlook movers (`core/mailbox/write.py`), migration `0003`, the response-service and route rules (policy cannot approve mail, `/result` refuses mail, `kind` filter), the write-consent sign-in (`connect --write`, scope allow lists, separate token files), the poller hook (proposes only), the runner (`core/mailbox/quarantine.py`) and its wiring in the app, the `quarantine` field in the mailbox status, and the console wording. Tests: `tests/unit/test_mail_write.py` (102) and `tests/unit/test_mail_quarantine.py` (98, flow end to end against fakes, planted message id never leaves the action row); a mutation run over 38 mutants had all real ones caught. **Found and fixed on the way:** a CHECK that let a mail action with no provider through (SQL accepts NULL), and a migration that did not run on SQLite (now batch mode). Migration `0003` passes on SQLite and on real PostgreSQL (upgrade from `0002` with data, the CHECK rules, downgrade, and the match against the models). **Not verified:** anything on real mailboxes.

**Original status (2026-11-05): approved by you.** You chose "Email quarantine (M6b)" in answer to a question that named the wider permission it needs. Built the same way as M5/M5b: against fakes only, never run against real Google or Microsoft.

**Goal:** a MALICIOUS email can be moved out of the inbox into a quarantine place **by you, with one click, and moved back with one click**. Nothing is deleted, nothing is sent. **Done when:** the whole flow (flag, approve, move, restore) passes against the fake Gmail and fake Graph, the write permission is a separate consent with its own token, and no code path can delete or send.
**Not in M6b:** auto-quarantine of mail, SUSPICIOUS mail, deleting or purging, other folders than the inbox, a live run (yours).

## What I found out first (official documentation, read 2026-11-05)

| Topic | Confirmed | Not stated / not verified |
|---|---|---|
| Gmail scope | `users.messages.modify` accepts only `mail.google.com`, `gmail.modify`, `gmail.modify.restricted`. `gmail.labels` ("see and edit your email labels") is **not** accepted for it. `gmail.modify` is a **restricted** scope described as "Read, compose, and send emails"; it excludes immediate permanent deletion | whether an app in "Testing" status with you as test user works without verification (the page says unverified apps need a verification request for public use) |
| Gmail call | `POST /gmail/v1/users/me/messages/{id}/modify` with `addLabelIds`/`removeLabelIds` (up to 100 each); returns the Message (with `labelIds`). `INBOX` can be applied and removed; labels are created with `POST /users/me/labels` (needs `gmail.modify`, `gmail.labels` or full) | what happens on a duplicate label name; whether `modify` repeats safely; whether removing `INBOX` is documented as "archive" |
| Graph call | `POST /me/messages/{id}/move` with `destinationId` (folder id or a well-known name); needs delegated `Mail.ReadWrite` (least and only); `201 Created` with the message; "creates a new copy of the message in the destination folder and removes the original". `inbox` is a documented well-known folder name for `GET /me/mailFolders/{name}` | that the **id changes** after a move (stated for regular ids on the immutable-id page, not on the move page); whether `inbox` is accepted as a `destinationId` (so I resolve the real inbox id first); duplicate folder name behaviour; `$filter` on folder `displayName` (so I list and match in code) |
| Graph permission | `Mail.ReadWrite` delegated: "create, read, update, and delete email … does not include permission to send mail"; admin consent **not** required for delegated use, per the permissions table | work-account specifics beyond that table |

## Decisions (my recommendation is what I build; say if you want a change)

| # | Decision | Recommendation |
|---|---|---|
| D1 | The permission | A **separate, explicit consent with its own token file**. The reading poller keeps its read-only token and never uses the write one. `python -m core.mailbox connect --provider gmail|outlook --write`. Gmail asks for `gmail.modify`; Outlook for `Mail.ReadWrite offline_access`. After sign-in the granted scopes are checked against a tight allow list; **any send, compose, full-access or file scope is refused and nothing is stored** |
| D2 | What "quarantine" is | Gmail: add the label `MIRAGE-Quarantine`, remove `INBOX`. Outlook: move to a folder `MIRAGE Quarantine`. **Restore** puts it back in the inbox. Nothing goes to Trash, nothing is deleted, and the mail stays visible to you in that label or folder |
| D3 | Who acts | The **core** (it already holds the mailbox tokens), from a small runner. The agent never sees mail actions: the action list can be filtered by kind, the agent asks for files only, and the result route refuses to finish a mail action. Same state machine, audit and console as files |
| D4 | Policy | Only **MALICIOUS** mail creates a pending action, and only if the write permission for that provider is connected. **Always your click**: `auto` mode never applies to mail (a wrong mail move costs more than a wrong file move). SUSPICIOUS is never moved |
| D5 | What is stored | The provider's opaque message id and the provider name, on the action row only (needed to find the message again). Never returned by the API, never logged, cleared when the action is restored. This relaxes ADR-017's "only a hash"; PRIVACY and the ADR addendum say so |
| D6 | Safe to repeat, safe to crash | Check, then act: read the message's current labels/folder first and do nothing if it is already where it should be; verify the result afterwards. One action per message. Outlook's new message id is saved in the same commit that marks the action applied. **Known gap:** a crash in the milliseconds between Outlook's reply and that commit leaves the mail in the quarantine folder with the action FAILED (`message_gone`): nothing lost, you move it back by hand |
| D7 | Egress | A **second, narrower guard** for the write client: HTTPS to the same hosts, and only these requests: Gmail `GET`/`POST` on labels, `GET` and `POST …/modify` on one message; Graph `GET` folders, `POST /me/mailFolders`, `GET` a message, `POST …/move`. **No DELETE, no PUT/PATCH, no send, no draft** — tested by trying each. Modify bodies may contain only the two label lists; move bodies only `destinationId` |
| D8 | Dependencies | None. Migration `0003`: new action kind `MAIL_QUARANTINE`, columns `provider` and `mail_ref` |

## Security implications

**New:** a credential that can change your mailbox, and code that uses it. **Controls:** separate consent and token (D1); granted-scope allow list; the narrow guard (D7) so MIRAGE's own code cannot delete or send even though the token could; always a human click (D4); reversible (D2); audit rows for every step with actor, provider and a hash prefix, never an id, address or subject (D5); the message id never leaves the action row.
**Residual:** the token is more powerful than MIRAGE's use of it: a program running as you that can decrypt it could send mail (Gmail) or delete mail (Graph) — the DPAPI file is protected from other users, not from your own session. Google's restricted scope means tokens last 7 days while the project is in "Testing", and public use would need Google's verification. A mail provider could change its behaviour (unverified rows above).

## Acceptance criteria

1. **Flow:** against the fake Gmail and fake Graph, a MALICIOUS mail creates a pending action (write permission connected); approve moves it (labels / folder verified from the reply); restore moves it back; the audit log shows each step.
2. **Not without consent:** with only the read token connected, no action is created and nothing is written; a write token with an extra scope (send, compose, full access, Mail.Send, files) is refused and not stored.
3. **Never delete, never send:** the write guard refuses DELETE, PUT, PATCH, send, drafts, trash and any other path or body (each tried); a test searches the mailbox code for delete/send/trash calls.
4. **Idempotent and fail-safe:** approve twice, restore twice, a repeated runner pass, a message already in place, a message that vanished, a provider error, throttling, a revoked write token: each ends in one stated state, never "done" by guess. Outlook id change handled.
5. **Separation:** the agent never receives a mail action; the result route refuses mail actions; `auto` never approves mail; SUSPICIOUS creates nothing.
6. **Privacy:** planted markers (message id, address, subject) never appear in API output, logs or audit rows; the id is cleared on restore.
7. **Console:** mail actions are shown with plain wording ("moves the message out of your inbox; nothing is deleted"), approve and restore work, hostile text is shown as text.
8. Existing suites, lint, secret scan, docs (ADR-017 addendum, PRIVACY, THREAT_MODEL, LIMITATIONS, OPERATIONS).
9. **Not claimed:** that Google or Microsoft accept these calls, that the verification/consent works for your account, or anything about real mailboxes.

## Build order (tests alongside; full suites at the end)

1. Migration `0003`, kind and columns, action creation for mail, the `kind` filter, the result-route rule, `auto` exclusion.
2. Write-consent sign-in for both providers (scope allow lists, separate token files, CLI `--write`).
3. The narrow write guard and the two quarantine clients, with the fakes extended (labels, folders, moves).
4. The runner in the core (APPROVED and RESTORE_REQUESTED mail actions), hook from the poller.
5. Console wording and the agent's file-only filter.
6. Docs, mutation checks, full suites, commit.
