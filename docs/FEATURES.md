# Lynceus: Features

*Everything Lynceus can do, feature by feature, with an honest status for each.*
Written 2026-11-10 from the code (URL ruleset 1.1.0, email and file ruleset 1.3.0). How each part is built: [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md). What does not work: [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

### Status labels

| Label | Meaning |
|---|---|
| **Verified** | runs on this machine and has passing tests; used live |
| **Tested** | built and passing its tests, but not yet used against real-world input |
| **Fakes only** | built and tested against a fake of the outside service; never run against the real one |
| **Needs key** | built; works only after you register with the provider and add your own key |
| **Off by default** | built; you turn it on in `.env` |
| **Not built** | planned or deferred |

---

## 1. At a glance

| Lynceus protects | How | Status |
|---|---|---|
| Your browsing (Edge, Chrome) | judges every page you open and shows a warning page before phishing | Verified (Edge); Chrome expected, not tested |
| Your downloads | judges every new file in Downloads, notifies you, offers quarantine | Verified |
| Files you are unsure about | drop them on the Analyze page for a full explanation | Verified |
| Your email | reads Gmail or Outlook (read-only) and judges every new message | Fakes only |
| Unknown Office macros | reads the macro's code and works out what it would do | Tested (synthetic macros) |
| Known phishing and malware | matches against OpenPhish, PhishTank and local hash lists | Verified (lists on) |

Every answer is one of five verdicts: **MALICIOUS**, **SUSPICIOUS**, **BENIGN**, **UNKNOWN**, **ERROR**, always with a score, the reasons, and the evidence. "UNKNOWN" is never treated as safe.

---

## 2. Browser protection (extension + agent)

| Feature | What it does | Status |
|---|---|---|
| Page check on every navigation | each top-level page you open is judged by the local engine in tens of milliseconds | Verified |
| Warning page | a phishing-looking page is replaced by a full-page warning with the verdict, the score and the reasons | Verified |
| Block before load | a URL already judged bad is stopped before any request leaves the browser on the next visit (up to 500 rules) | Verified, needs optional site access; intermittent in automation |
| Check after redirects | the page a redirect chain ends on is judged as well | Verified |
| "Continue anyway" | you can still open a flagged page for 15 minutes; the agent records it; a web page cannot fake this | Verified |
| Never slows browsing | the check runs beside the page load; nothing waits on the network | Verified |
| Honest failure | toolbar badge red `!` when the agent is down, amber `?` when the engine is down; pages then load unchecked | Verified |
| Popup | shows protection state, pages judged and checks waiting | Verified |
| Notification | a Windows notification when a phishing page was stopped or warned about (host only) | Verified |
| Privacy | verdicts cached by a hash of the URL, not the URL; nothing sent to any website | Verified |
| Frames inside pages | not judged (only the top-level page) | Not built |
| Firefox | not supported | Not built |

---

## 3. Download and file protection (agent)

| Feature | What it does | Status |
|---|---|---|
| Downloads watcher | every new file in Downloads is judged automatically, with no window open | Verified |
| Waits for complete files | judges a file only after it has been quiet for 1 s and can be opened; gives up after 10 minutes locked | Verified |
| Survives restarts | waiting files are spooled to disk; a checkpoint and re-scan catch what the watcher missed | Verified |
| Source of the download | reads the browser's Mark of the Web to learn which host a file came from (host only) | Verified |
| Notifications | a Windows notification for a malicious or suspicious file, with the reason | Verified (visibility depends on Focus Assist) |
| Large files | files over 16 MiB are judged by name, size, type and hash, not opened | Verified |
| Starts at logon | per-user Run entry; no administrator rights | Verified |
| Supervises the engine | starts the Python engine and restarts it if it stops | Verified |

---

## 4. Deep file inspection (in the sandbox)

Every file is opened by a separate locked-down process (Windows AppContainer + Job Object: no network, 512 MB, 10 s CPU, one process). Nothing is ever run.

| File kind | What is found | Status |
|---|---|---|
| Real type vs name | a file whose content does not match its extension (an `.exe` named `.pdf`) | Verified |
| Scripts (PowerShell, JScript, VBScript, batch, HTA) | downloaders, encoded commands, up to 4 hidden layers of encoding, living-off-the-land binaries, persistence, turning off defences, process injection, credential theft, fake password prompts, sandbox detection | Tested |
| Windows shortcuts (`.lnk`) | a shortcut that launches an interpreter; a shortcut disguised as a document | Tested |
| Windows programs (PE) | packing; imports used for injection or downloading; programs hidden inside other files | Tested |
| PDF | JavaScript, Launch actions, embedded files, XFA forms, encryption, links | Verified |
| Archives (ZIP, TAR, gzip, bzip2, xz) | dangerous contents, double extensions, macros inside, nesting (3 levels), path traversal, encryption, zip bombs | Verified |
| Images | QR codes (decoded and the link judged), image bombs | Verified |
| Office documents | macros, auto-run macros, remote templates, DDE, Equation Editor objects, embedded objects | Tested |
| Office macros (unknown) | see section 5 | Tested (synthetic) |
| HTML attachments | HTML smuggling (a file assembled inside the page) | Verified |
| Known-bad hashes | SHA-256, SHA-1 and MD5 matched against local lists; a match is decisive | Verified |
| EICAR test file | recognised as the standard antivirus test file | Verified |
| 7z, RAR, ISO | recognised by type only, not opened | Not built |
| Text inside images (OCR) | not read | Not built (deferred) |
| Password-protected files | reported as such; contents unknown | Tested |

A file is never called BENIGN: the best a clean file gets is UNKNOWN.

---

## 5. Office macro analysis: catching macros nobody has seen before

Lynceus reads a macro the way an analyst would, instead of looking it up in a list.

| Feature | What it does | Status |
|---|---|---|
| VBA extraction | from `.doc`, `.xls`, `.ppt` and from `.docm`, `.xlsm`, `.pptm` | Tested |
| **Code evaluator** | runs only the macro's own string-building code (44 safe built-ins, hard limits) to recover hidden commands and URLs in plain text | Tested |
| Auto-run to danger | follows the call graph from `AutoOpen` / `Document_Open` / `Workbook_Open` to a dangerous call (shell, download, script host) | Tested |
| Hidden behaviour | flags a command or URL that appears only after decoding | Tested |
| Windows API abuse | `Declare` of memory, thread, process or download functions (`VirtualAlloc`, `CreateThread`, `URLDownloadToFile`, ...) | Tested |
| Dynamic calls | `CallByName`, `Application.Run`, computed `CreateObject`, `Evaluate`, `ExecuteExcel4Macro` | Tested |
| Hidden data stores | code that reads its payload from document properties, custom XML, document variables, form captions, tooltips, alt text | Tested |
| File drop | writing a file into Temp, AppData, Public, ProgramData or Startup | Tested |
| Obfuscation | at least two signs of machine-made code (many `Chr` calls, mass concatenation, random names, long number arrays, very long lines) | Tested |
| VBA stomping | source that is missing or does not match the compiled p-code | Tested |
| Excel 4.0 (XLM) macros | in `.xlsm`: formulas evaluated; in `.xls`: macro sheets, hidden sheets and `Auto_Open` found | Tested |
| **Local AI reviewer** | see section 11 | Off by default |

Measured on synthetic macros: 8 of 8 unknown malicious macros flagged (7 MALICIOUS), 0 of 10 ordinary macros fire a new rule. **No real-world Office malware has been tested yet.**

---

## 6. Email analysis

| Feature | What it does | Status |
|---|---|---|
| Full MIME parsing in the sandbox | headers, every part, nested messages, malformed MIME | Verified |
| Sender checks | several From addresses, a brand in the display name, Reply-To going elsewhere, lookalike sender domains (homograph, typosquat, combosquat, brand in subdomain) | Verified |
| Authentication | SPF, DKIM and DMARC `fail` / `softfail` read from `Authentication-Results` | Verified |
| Links | every link judged by the URL engine; link text that names one site but points to another; hidden links; image-only links; link floods | Verified |
| HTML tricks | password forms, scripts, meta refresh, hidden text, Outlook conditional comments, VML links | Verified |
| Social engineering | urgency and credential requests in English and Polish | Verified |
| Attachments | dangerous types, double extensions, right-to-left filename tricks, type mismatch, macros, HTML attachments, archives; up to 8 opened per message, each in its own sandbox | Verified |
| QR codes in images | decoded and the link judged | Verified |
| Never "safe" | a message is never BENIGN; a clean one is UNKNOWN | Verified |
| `.eml` from the command line | `python -m core.cli analyze-eml <file>` | Verified |

---

## 7. Live mailboxes

| Feature | What it does | Status |
|---|---|---|
| Gmail, read-only | every new message judged once, missed mail found again, notification when flagged | Fakes only |
| Outlook / Microsoft 365, read-only | same, through Microsoft Graph | Fakes only |
| Secure sign-in | OAuth 2.0 with PKCE on a loopback address; tokens encrypted with Windows DPAPI | Fakes only |
| Re-connect notice | the agent tells you once when a mailbox needs signing in again | Fakes only |
| Email quarantine | a MALICIOUS message moved to a `Lynceus Quarantine` label or folder, only with a separate, explicit write permission and your click; restorable | Fakes only |
| Cannot delete or send | the code is held to a fixed set of requests by a guard | Fakes only |
| Disconnect | `python -m core.mailbox disconnect` deletes the token and asks the provider to revoke it | Fakes only |
| IMAP, other folders | inbox only, no IMAP | Not built |

---

## 8. URL detection (20 rules)

Each rule gives one reason in plain words. One reason alone never makes a URL MALICIOUS.

| Rule | Catches |
|---|---|
| IP address host | `http://203.0.113.5/login` |
| Obfuscated IP | `http://3405803781/`, hex or octal IPs |
| Userinfo trick | `https://paypal.com@evil.example/` |
| Homograph brand | `аllegro` with a Cyrillic `а`, punycode lookalikes |
| Mixed scripts | Latin and Cyrillic or Greek letters in one name |
| Typosquat | `paypa1`, `arnazon`, `micosoft` |
| Combosquat | `paypal-login`, `secure-mbank` |
| Brand in subdomain | `paypal.com.evil.example` |
| Brand in domain (weak) | an unrelated domain containing a brand |
| Shortener (weak) | `bit.ly` and 17 others: destination unknown |
| Open redirect | a parameter that sends you to another site (share dialogs excluded) |
| Encoded target | an off-site address hidden by double or base64 encoding |
| Credential bait | a brand and a login word in the path of a site the brand does not own |
| Prefilled identity | your email address already filled in the link |
| Login path (weak) | a path ending in a login or verify page |
| Dangerous scheme | `javascript:`, `data:`, `file:` |
| Odd port | a port other than 80, 443, 8000, 8080, 8443 |
| Very long URL | 2,000 characters or more |
| Odd host shape | many hyphens or many subdomain levels |
| Parser tricks | backslashes, control or invisible characters, encoded host, double encoding in the path |

Brand list: 105 brands (global and Polish) with 189 official domains. Official sites are recognised as BENIGN, except shared hosting where anyone can publish (Google Sites, Docs, Drive, GitHub, Dropbox, Azure blob storage, ...). Analyze one URL offline: `python -m core.cli analyze-url <url>`.

---

## 9. Email and file rules (80)

| Area | Rules |
|---|---|
| Decisive | known-bad hash, EICAR |
| Attachments | dangerous attachment, double extension, right-to-left name, type mismatch, macro attachment, HTML attachment, archive attachment |
| Archives | bomb, encrypted, path traversal, dangerous contents, double extension inside, macro inside, nested archive |
| PDF | JavaScript, Launch action, embedded file, XFA form, encrypted |
| Images | QR code link, image bomb |
| HTML and links | link text names another brand, link text mismatch, hidden link, image-only link, password form, script, meta refresh, link flood, HTML smuggling |
| Sender | multiple From, brand in display name, Reply-To mismatch, authentication failure, sender homograph, mixed script, typosquat, combosquat, brand in subdomain, brand in domain |
| Message | malformed MIME, parser limits reached, file inspection incomplete, social engineering |
| Scripts and programs | downloader, encoded command, hidden layers, evasive launch, persistence, LOLBin, defence evasion, process injection, credential access, credential prompt, anti-analysis, embedded executable, disguised program, packed program, injection or downloader imports |
| Shortcuts | runs an interpreter, disguised as a document |
| Office | macro, auto-run macro, remote template, DDE, Equation Editor, embedded object |
| Macro behaviour | hidden behaviour, auto-run reaches a dangerous call, API import, dynamic dispatch, hidden data source, file drop, obfuscated, VBA stomped, p-code only, XLM macro, hidden XLM sheet |

Rules are tagged with **27 MITRE ATT&CK techniques** (e.g. T1566.001 spearphishing attachment, T1566.002 link, T1204.002 malicious file, T1059 scripting, T1105 tool transfer, T1218 signed binary proxy, T1564.007 VBA stomping, T1106 native API, T1221 template injection, T1559.002 DDE).

---

## 10. Threat intelligence

| Source | What it adds | Status |
|---|---|---|
| OpenPhish community feed | exact phishing URLs, downloaded and matched on this machine | Verified (on) |
| PhishTank | exact phishing URLs, downloaded and matched on this machine | Verified (on) |
| Automatic refresh | lists refreshed in the background; a stale list reports itself unavailable instead of matching old data | Verified |
| URLhaus | malware URLs | Needs key |
| MalwareBazaar | recent malware hashes into the local hash lists | Needs key |
| VirusTotal | domain reputation (sends only the bare domain) | Needs key, off |
| urlscan.io | domain verdicts (sends only the bare domain) | Needs key, off |
| RDAP domain age | young domains (sends only the bare domain) | Off by default |
| Resilience | timeouts, rate limits, circuit breakers, caching; a provider that fails is shown as failed, never "safe" | Tested |
| One provider is never enough | a single listing gives SUSPICIOUS at most; nothing from intel ever gives BENIGN | Verified |
| Local hash lists | `python -m core.intel hashes import|check|sync|status` | Verified |
| Command line | `python -m core.intel sync|status|lookup <url>` | Verified |

---

## 11. Local AI reviewer (advice only)

| Feature | What it does | Status |
|---|---|---|
| Second opinion on macros | a local model (`llama3.2:3b` via Ollama, on this computer only) reads the macro's code and decoded strings | Off by default (`LYNCEUS_LLM_REVIEW=true`) |
| Fixed-form answers | malicious / suspicious / benign / unsure, a confidence, behaviours from a fixed list; no free text shown | Tested |
| Cannot decide | adds at most one weak signal; never lowers a verdict; never makes one MALICIOUS on its own | Tested |
| Prompt-injection guard | comments stripped from the code before the model sees it | Tested |
| Never blocks a verdict | 45-second limit; the verdict goes out without the model if it is late | Tested |
| Private | sent to `127.0.0.1` only, not stored | Tested |
| Measured | 24 of 24 test macros answered and agreed (6 written independently) | Tested |
| Mailbox messages | the reviewer does not run in the mailbox poller | Not built |

---

## 12. Verdicts and explanations

| Feature | What you get |
|---|---|
| Five verdicts | MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN, ERROR |
| Risk score | 0 to 100, from a published formula (noisy-OR per category, capped, then across categories) |
| Confidence | LOW, MEDIUM, HIGH, from how many independent kinds of evidence agree |
| Reasons | every signal with its rule, category, weight, plain-language description and ATT&CK technique |
| Evidence | what was found and where, linked to each signal |
| Provider results | which source said what, and when |
| Recommendation | BLOCK (MALICIOUS), WARN (SUSPICIOUS), NONE |
| Two-key rule | MALICIOUS needs score ≥ 80 **and** strong evidence of two independent kinds |
| Versioned | each verdict names the engine and ruleset version (with a hash of the rule data) that produced it |
| Editable scoring | weights, caps and thresholds are TOML files you can read and change |
| Export | `python -m core.export [--since ISO] [--out FILE]` writes verdicts as JSON lines for a SIEM |

---

## 13. Responses and quarantine

| Feature | What it does | Status |
|---|---|---|
| Ask first (default) | a MALICIOUS file gets a proposed quarantine; you approve in the notification or the console | Verified |
| Automatic mode | `ResponseMode: auto` quarantines MALICIOUS files without asking | Verified, off by default |
| Off mode | `ResponseMode: off`: verdicts and notifications only | Verified |
| Safe move | the file's SHA-256 must still match the judged one; across drives it is copied, verified byte for byte, then the original removed | Verified |
| Never deletes | quarantine moves; nothing is ever deleted | Verified |
| One-click restore | puts the file back exactly where it was, with its Mark of the Web | Verified |
| Idempotent | repeating an action is harmless; an impossible step is refused | Verified |
| Audit log | every approve, dismiss, restore and result is recorded | Verified |
| Allow-list | stop proposals for one exact file content | Verified |
| Only MALICIOUS | SUSPICIOUS files are never moved | Verified |

---

## 14. Console and analysis workbench

Open with `Lynceus.Agent.exe --open-console`, or in the native window (Tauri).

| Page | What you can do | Status |
|---|---|---|
| Analyze | paste a link, drop an `.eml` or any file; see the verdict, score, every reason, the anatomy of the link, the evidence and the provider results | Verified |
| Events | every stored verdict with its evidence | Verified |
| Actions | approve, dismiss or restore quarantine actions | Verified |
| Allow-list | see and remove allowed content | Verified |
| Audit | the full audit log | Verified |
| Themes | light and dark, colour contrast at WCAG AA | Verified (contrast computed) |
| Native window | the console in its own desktop window (Tauri 2) | Built |
| Screen readers | semantic markup only; not tested with a screen reader | Not verified |

---

## 15. Privacy

| Feature | Detail |
|---|---|
| Local-first | the engine, database and model all run on this computer, on loopback addresses |
| Nothing stored that identifies content | no URL text, message body, subject, address or file name in the database; hosts only; a test checks every table |
| Outside services off by default | each provider must be named in `.env`; query providers receive only a bare domain |
| One exit door | all outbound traffic goes through one egress module; a test fails if any other code opens a connection |
| Secrets protected | API and mailbox tokens under Windows DPAPI; logs redacted; a secret scan runs before every commit |
| Your browsing history | used once for the E1 evaluation, read locally, counts only, never stored |

Full detail: [PRIVACY.md](PRIVACY.md).

---

## 16. Security hardening

| Feature | Detail |
|---|---|
| Sandboxed parsing | AppContainer (no network, read-only access to its own folder) + Job Object limits; output checked against a fixed vocabulary of 41 indicators |
| Bomb protection | archive, image and PDF bombs stopped by size, ratio and count limits |
| Locked-down API | loopback only, Host header check, bearer token, no CORS, rate limits, size limits |
| Local IPC | named pipe for the current user only, with a per-install secret |
| SSRF guard | redirect resolver re-checks every hop and every resolved IP (built, off) |
| Pinned parsers | sandbox libraries installed by hash |
| Independent review | two reviewers attacked the code (R1); findings fixed or listed |
| Packaged-app trap | installers refuse to run inside a packaged app's private registry and check Windows' own view |
| Folder permissions | `install.ps1 -HardenAcl` restricts the checkout to you, SYSTEM and Administrators |

---

## 17. Installation and operations

| Feature | Detail | Status |
|---|---|---|
| One-command install | `deploy\install.ps1`: builds and installs everything per-user, no administrator rights | Verified |
| Go-live / upgrade | `deploy\go-live.ps1` (with `-CheckOnly` to verify without changes) | Verified |
| Uninstall | `deploy\uninstall.ps1`; `-RemoveData` refuses while files are still quarantined | Verified |
| MSI installer | per-user WiX MSI (`deploy\msi\build-msi.ps1`) | Built, unsigned |
| Agent commands | `--install`, `--uninstall`, `--status`, `--open-console` | Verified |
| Database | PostgreSQL 17 in Docker (`python tasks.py up`), migrations (`python tasks.py migrate`) | Verified |
| Task runner | `python tasks.py up | test | eval | lint | migrate | sandbox | deps | serve | fmt | secrets | hooks` | Verified |
| Code signing | not signed | Not built |
| CI | a workflow exists but has never run | Not verified |

---

## 18. Quality measurement

| Tool | What it measures |
|---|---|
| `python -m eval` | precision, recall, F1, abstain rate and 95% intervals on the labelled synthetic corpus (dev / holdout / sealed reserve) |
| `python -m eval.realurl` | the URL engine on ~300,000 real URLs (PhiUSIIL, PhishTank, OpenPhish, Tranco, your own browsing locally) |
| `python -m eval.perf` | latency and throughput on this machine |
| Test suites | 2,540 Python tests, 349 agent tests, 114 + 7 extension tests, 60 + 12 console tests |
| Rule fixtures | every rule has at least one positive and one negative example, enforced by a test |

### The honest results

| Measurement | Result |
|---|---|
| URL rules on synthetic samples | precision 1.000, recall 0.966 |
| Email rules on synthetic samples | precision 1.000, recall 0.973 |
| **URL rules on real phishing (E1, 133,195 URLs)** | **2.5% caught**; 22.9% of OpenPhish's fresh URLs |
| Real phishing where no URL rule fires at all | 91.2% |
| False alarms on real legitimate URLs (166,265) | 0.3% |
| False alarms on the owner's own browsing | 0 of 87 (after ruleset 1.1.0) |

The synthetic numbers show the rules do what they were written to do. The real-data number shows the limit of reading an address alone: today Lynceus catches a new phishing link mainly when OpenPhish or PhishTank already lists it.

---

## 19. Not built yet (the road ahead)

| Feature | Why it matters |
|---|---|
| Page detonation sandbox | 91% of real phishing URLs show nothing in the address; only the page itself does |
| Visual brand matching | recognise a fake login page by how it looks |
| Sender and relationship profiling | "this sender has never written to you before" |
| AI intent analysis for email text | understand the request in the message, not only keywords |
| Domain age and certificate transparency | catch freshly registered phishing domains |
| Password-reuse warning | warn when you type a known password into an unknown site |
| Campaign memory | link related messages, URLs and files |
| Feedback buttons | let you mark a verdict right or wrong |
| Frame checking | judge pages loaded inside other pages |
| Live Gmail / Outlook run | everything there is tested against fakes only |
| Signed installer, CI | trust and repeatability |
| More file types | 7z, RAR, ISO, OCR of images |
