# Operating MIRAGE

For one person on one Windows 11 machine. Everything runs as you; nothing needs administrator rights.

## Install, upgrade, uninstall

Prerequisites: Python 3.14, .NET 10 SDK, Node 24, PostgreSQL (`python tasks.py up` starts one in Docker), a checkout with `.venv` and a `.env` (copy `.env.example`; set `MIRAGE_API_TOKEN` and `MIRAGE_DATABASE_URL`).

| Do | Command |
|---|---|
| Install or upgrade | `.\deploy\install.ps1` (options: `-InstallDir`, `-CorePort`, `-NoRegister`, `-NoStart`, `-ResetConfig`, `-SkipMigrate`) |
| Uninstall, keep your data | `.\deploy\uninstall.ps1` |
| Uninstall and delete your data | `.\deploy\uninstall.ps1 -RemoveData` (**also deletes the quarantine folder: those files are gone for good**) |
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
| Threat-intelligence lists, Gmail state | `.data/` in the checkout (`MIRAGE_DATA_DIR`) |

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

**The core** reads `MIRAGE_*` variables and `.env` (see `.env.example` and `core/config.py`): `MIRAGE_API_TOKEN`, `MIRAGE_DATABASE_URL`, `MIRAGE_RATE_LIMIT_PER_MINUTE` (120), `MIRAGE_MAX_CONCURRENT_PARSERS` (4), `MIRAGE_MAX_MESSAGE_BYTES`, `MIRAGE_MAX_FILE_BYTES`, `MIRAGE_INTEL_PROVIDERS` (off), `MIRAGE_GMAIL_*` (off), `MIRAGE_CONSOLE_DIR`. The agent passes its own token and a short intelligence deadline to the core it starts, which override `.env`.

## Day to day

- **Nothing to do.** The agent starts at logon and keeps the core running. The extension's toolbar badge is empty when all is well, `!` when the agent is not running (pages then open unchecked), `?` when the agent is up but cannot reach the core.
- **Decide on a flagged file:** the console, Responses page. Nothing moves until you confirm (in `ask` mode).
- **Gmail:** `python -m core.mailbox connect` once (needs your own Google OAuth client, see `docs/milestones/M5.md`), set `MIRAGE_GMAIL_ENABLED=true`, restart the agent. While the Google project is in "Testing" the connection lapses after 7 days and the agent tells you.
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
| A test or build fails with a locked file | the running agent holds its own DLLs: stop it, or build in Release |

## Limits worth knowing

Blocking in the browser fails open by design and the first visit to a new URL can start loading before the verdict arrives; files are flagged and optionally quarantined, never deleted; email is read-only; the sandbox and the agent are Windows-only. The full list, with what was and was not verified, is [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).