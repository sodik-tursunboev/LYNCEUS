# Operating MIRAGE

For one person on one Windows 11 machine. Everything runs as you; nothing needs administrator rights.

## Install, upgrade, uninstall

Prerequisites: Python 3.14, .NET 10 SDK, Node 24, PostgreSQL (`python tasks.py up` starts one in Docker), a checkout with `.venv` and a `.env` (copy `.env.example`; set `MIRAGE_API_TOKEN` and `MIRAGE_DATABASE_URL`).

| Do | Command |
|---|---|
| Install or upgrade | `.\deploy\install.ps1` (options: `-InstallDir`, `-CorePort`, `-NoRegister`, `-NoStart`, `-ResetConfig`, `-SkipMigrate`, `-HardenAcl`, `-Force`). It refuses a drive root, your profile folder or a non-empty folder that is not a MIRAGE install, and fails if another MIRAGE agent is already running from somewhere else. It **warns when other accounts on the computer can change the checkout** (the core runs from it with your rights); `-HardenAcl` restricts the checkout to you, SYSTEM and Administrators |
| Uninstall, keep your data | `.\deploy\uninstall.ps1` |
| Uninstall and delete your data | `.\deploy\uninstall.ps1 -RemoveData` (**also deletes the quarantine folder: those files are gone for good**). It refuses while quarantined files have not been restored (restore them in the console first, or add `-Force`), and it refuses a folder that does not look like MIRAGE's. `-RemoveSandbox` also removes the parser sandbox |
| See what is registered | `Mirage.Agent.exe --status` |
| Register / unregister only | `Mirage.Agent.exe --install` / `--uninstall` |
| Open the console, signed in | `Mirage.Agent.exe --open-console` |
| Store the core's API token | `Mirage.Agent.exe --set-token` (reads it from standard input) |

The install script builds the agent, the extension and the console, copies the agent and the extension to `%LOCALAPPDATA%\Programs\Mirage`, writes `agent.json` if there is none (an existing one is kept), applies database migrations if `.env` names a database, registers start at logon and the Edge/Chrome native-messaging host, starts the agent and waits until the core answers. **An upgrade is the same command**: the running agent is stopped, its files replaced, your data folder untouched, and the agent started again. The core runs from the checkout (its Python environment, the sandbox, the console), so keep the checkout where it is or run the script again after moving it. The browser extension is added by hand (`edge://extensions`, Developer mode, Load unpacked, `...\Mirage\extension`); the installer cannot do that for you.

## Where things are

| What | Where |
|---|---|
| Agent and extension files | `%LOCALAPPDATA%\Programs\Mirage` (or `-InstallDir`) |
| Agent data: config, logs, spool, quarantine, secrets | `%LOCALAPPDATA%\Mirage` (or `MIRAGE_AGENT_HOME`) |
| The core | the checkout; listens on `127.0.0.1:8765` |
| Console | `http://127.0.0.1:8765/console/` |
| Database | the PostgreSQL named in `.env` (`MIRAGE_DATABASE_URL`) |
| Threat-intelligence lists, Gmail and Outlook state | `.data/` in the checkout (`MIRAGE_DATA_DIR`) |

Files in the data folder: `agent.json` (settings), `agent.log` and `core.log` (rolling, about 1 MB each plus one old copy), `spool.jsonl` (files waiting to be judged), `flagged.json` (which local file each proposed response is about), `state.json` (what the file watcher has seen), `core.token` (the API token, encrypted for your Windows user), `pipe.secret` (the pipe password, plain text, readable only by you through folder permissions), `quarantine\<id>\` (quarantined files).

## Settings

**`agent.json`** (unknown keys and out-of-range values stop the agent from starting; the reason is in `agent.log`):

| Key | Default | Meaning |
|---|---|---|
| `CoreUrl` | `http://127.0.0.1:8765` | where the core listens; loopback only, enforced |
| `CoreCommand`, `CoreArgs`, `CoreWorkingDir` | none | how the agent starts the core (the install script fills them); without `CoreCommand` someone else must run the core |
| `ResponseMode` | `ask` | `ask`: a malicious file waits for your click in the console; `auto`: quarantine it at once; `off`: never act. Suspicious files are never moved |
| `WatchFolders`, `IncludeSubfolders` | Downloads, no | folders to watch |
| `StableMillis` | 1000 | a file is judged after this long without a change |
| `GiveUpSeconds` | 600 | stop waiting for a file that stays locked |
| `MaxInspectBytes` | 16 MiB | larger files are described, not opened |
| `CoreIntelDeadlineSeconds` | 0.5 | how long a browser check waits for threat-intelligence providers |
| `InitialLookbackHours` | 0 | on the very first start, also look at files this recent |
| `DataDir` | the data folder | where state lives |
| `MaxPendingPaths`, `MaxSpoolRecords`, `MaxKnownIds`, `MaxRescanFiles`, `MaxAttempts`, `RetryBaseMillis`, `RetryMaxMillis`, `TickMillis`, `WatcherBufferBytes` | see `AgentConfig.cs` | limits and timings |

**The core** reads `MIRAGE_*` variables and `.env` (see `.env.example` and `core/config.py`): `MIRAGE_API_TOKEN` (at least 16 characters; the `CHANGE_ME` placeholder is refused), `MIRAGE_DATABASE_URL`, `MIRAGE_RATE_LIMIT_PER_MINUTE` (120; files, overrides and the rest), `MIRAGE_URL_RATE_LIMIT_PER_MINUTE` (1200; the browser's URL checks have their own lane), `MIRAGE_MAX_CONCURRENT_PARSERS` (4), `MIRAGE_MAX_MESSAGE_BYTES`, `MIRAGE_MAX_FILE_BYTES`, `MIRAGE_INTEL_PROVIDERS` (off), `MIRAGE_GMAIL_*` (off), `MIRAGE_CONSOLE_DIR`. The agent passes its own token and a short intelligence deadline to the core it starts, which override `.env`.

## Day to day

- **Nothing to do.** The agent starts at logon and keeps the core running. The extension's toolbar badge is empty when all is well, `!` when the agent is not running (pages then open unchecked), `?` when the agent is up but cannot reach the core.
- **Installer (MSI):** `deploy\msi\build-msi.ps1 -Version 0.1.0` builds `deploy\msi\out\Mirage-0.1.0-x64.msi` (about 134 MB; needs the WiX tool 5.0.2, a built `.sandbox`, and the `.venv`). It installs per user, no administrator, to `%LOCALAPPDATA%\Programs\Mirage` (agent with its own .NET runtime, extension, a private Python with only the core's libraries, the core, the console and the built sandbox), registers the sandbox, writes `agent.json` and `engine\.env` if they do not exist, registers start-at-logon and the browser bridge, and starts the agent. Options on the `msiexec` line: `INSTALLFOLDER=`, `NOSTART=1`, `NOREGISTER=1`, `RESETCONFIG=1` (an existing `agent.json` that points elsewhere, for example at a checkout, is kept unless you set this). Put `MIRAGE_DATABASE_URL` in `engine\.env`, then run `engine\python\python.exe -m alembic upgrade head` from `engine` (or reinstall: setup applies migrations when the URL is set). A newer MSI upgrades in place; your data folder and `engine\.env` are never touched. Uninstall (Settings, Apps) leaves the data folder, `engine\.env` and the sandbox's per-user container profile. Setup and cleanup write `%LOCALAPPDATA%\Mirage\setup.log`. Never run against a clean machine or a real second user; not signed (ADR-007).
- **Open the console:** the MSI adds two Start-menu shortcuts, "MIRAGE" (its own native window, `shell\Mirage.Console.exe`: starts the agent if needed and signs in by itself) and "MIRAGE (in the browser)" (`Mirage.Agent.exe --open-console`). Building the window needs Rust (see `docs/DECISIONS.md` ADR-019); running it needs the WebView2 runtime, which Windows 11 includes.
- **Decide on a flagged file:** the console, Responses page. Nothing moves until you confirm (in `ask` mode).
- **Gmail:** `python -m core.mailbox connect` once (needs your own Google OAuth client, see `docs/milestones/M5.md`), set `MIRAGE_GMAIL_ENABLED=true`, restart the agent. While the Google project is in "Testing" the connection lapses after 7 days and the agent tells you.
- **Outlook / Microsoft 365** (never run live, see `docs/milestones/M5b.md`): register an app in your own Azure tenant (public client, redirect `http://localhost`, delegated `Mail.Read`), put its id in `MIRAGE_OUTLOOK_CLIENT_ID`, run `python -m core.mailbox connect --provider outlook`, set `MIRAGE_OUTLOOK_ENABLED=true`, restart the agent. `--provider outlook` also works with `status`, `poll` and `disconnect`. Both providers can run at once.
- **Email quarantine (optional, never run live, see `docs/milestones/M6b.md`):** a wider permission, given separately. First connect the normal read-only sign-in above, then `python -m core.mailbox connect --write` (add `--provider outlook` for Outlook; Outlook's app registration also needs delegated `Mail.ReadWrite`, Google's consent screen needs `gmail.modify`). It shows what the permission can do and wants you to type `YES`. After that a MALICIOUS message appears in the console's Responses page as an email action; **Approve** moves it out of the inbox (Gmail: label `MIRAGE-Quarantine`; Outlook: folder `MIRAGE Quarantine`), **Restore** moves it back. Nothing is deleted or sent, and `auto` mode never moves mail. `python -m core.mailbox status` shows `quarantine`: `none`, `ready` or `reauth_needed`. Withdraw the permission with `python -m core.mailbox disconnect --write`. Mail judged before you gave the permission is not proposed afterwards.
- **Known-bad file hashes:** every analysed file is hashed (SHA-256, SHA-1, MD5) and looked up in the lists in the `hashes` folder of the core's data folder (`.data\hashes` when the core runs from a checkout, `%LOCALAPPDATA%\Mirage\data\hashes` for an MSI install; `MIRAGE_DATA_DIR` moves it). `python -m core.intel hashes import C:\path\iocs.txt --name team` adds a list (one hash per line, or any CSV: only hash-shaped words are kept); `hashes check C:\path\file.exe` hashes a file and says if it is listed; `hashes status` shows the lists. `hashes sync` downloads MalwareBazaar's recent hashes (needs your own free abuse.ch key in `MIRAGE_URLHAUS_AUTH_KEY`; run at most every five minutes). A listed hash makes the file MALICIOUS by itself and names the list. The harmless EICAR test file is built in: it is how to see the whole path work (do not save it to disk; your antivirus will react).
- **Threat-intelligence lists:** off until you name providers; `python -m core.intel sync` downloads the lists.

## Back up

Back up the PostgreSQL database and the data folder (`%LOCALAPPDATA%\Mirage`, which holds the quarantine). `.env` holds keys in plain text: protect it like a password file. The API token can be regenerated by deleting `core.token` (restart the agent).

## When something is wrong

| Symptom | Look at |
|---|---|
| The core does not answer after install | `core.log` and `agent.log` in the data folder; is the database up (`python tasks.py up`)? |
| Pages open with no warnings and the badge shows `!` | the agent is not running: start `Mirage.Agent.exe`; check `Mirage.Agent.exe --status` |
| The extension says the host is not found | the bridge is registered per user: run `Mirage.Agent.exe --install`; load the extension from the folder the install script printed (its ID is fixed by the key in its manifest) |
| A dangerous file is not proposed for quarantine | responses need the database and migration `0002` (`python tasks.py migrate`); only MALICIOUS verdicts of files the agent saw are proposed |
| A file seems ignored | files that appear before the agent starts are not looked at; temporary names (`.crdownload`, `.tmp`) wait until renamed; files over 16 MiB are described, not opened; a file another security product blocks is skipped (`agent.log` says so) |
| The console asks for a token | open it with `Mirage.Agent.exe --open-console`, or type the token |
| Gmail says `reauth_needed` | `python -m core.mailbox connect` again |
| Outlook says `reauth_needed` | `python -m core.mailbox connect --provider outlook` again (Microsoft no longer accepts the saved sign-in) |
| An email action ends FAILED | the console shows the reason: `message_gone` (the message is not where it was; check the label/folder by hand), `mail_auth` (connect `--write` again), `mail_forbidden` (the provider refused: is the write permission still granted?), `mail_unavailable` (throttled or down for ten tries: approve again later), `no_write_access` (that provider is off or has no write permission), `mail_bad_reply`/`mail_error` (unexpected answer; nothing was claimed done). Approve again to retry |
| Mail quarantine says `reauth_needed` | `python -m core.mailbox connect --write` again (add `--provider outlook` for Outlook) |
| A test or build fails with a locked file | the running agent holds its own DLLs: stop it, or build in Release |

## Limits worth knowing

Blocking in the browser fails open by design and the first visit to a new URL can start loading before the verdict arrives; files are flagged and optionally quarantined, never deleted; email is read-only; the sandbox and the agent are Windows-only. The full list, with what was and was not verified, is [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).