# Lynceus: Features

*Everything Lynceus can do, feature by feature, with an honest status for each, what was added most recently, and what is expected next.*
Updated 2026-11-11 from the code (URL ruleset 1.1.0, email and file ruleset 1.3.0, page ruleset 1.0.0). How each part is built: [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md). What does not work: [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

### Status labels

| Label | Meaning |
|---|---|
| **Verified** | runs on this machine and has passing tests; used live |
| **Tested** | built and passing its tests, but not yet used against real-world input |
| **Fakes only** | built and tested against a fake of the outside service; never run against the real one |
| **Needs key** | built; works only after you register with the provider and add your own key |
| **Off by default** | built; you turn it on in `.env` |
| **Built** | built, not yet checked in daily use |
| **Planned** | expected future feature (section 20) |
| **Not built** | known gap, not scheduled |

---

## What's new

| Date | Added | Status |
|---|---|---|
| 2026-11-22 | **DA5, a smarter engine and agent:** `python -m core.cli investigate` (an offline evidence dossier for a link, message or file: anatomy, the learned model's reading, per-signal attribution that rebuilds the score, and verified counterfactuals); learned model 3 refitted on fresh feeds; the learned model is silent for Tranco ranks 100,001 to 1M; a sign-in service's `redirect_uri` weighs 0.3 and `oauth` is no login word; the browser tab gets the deeper sandbox verdict one re-ask later; plain-language explanations from one sentence per rule; a re-check queue (a link listed by a feed after you opened it raises one alert); an incident view linking a mail link, a download and a repeated file; a calibration of score bands and an ask table (not wired yet) (`docs/milestones/DA5.md`) | Verified (measured; ledger `GATES-DA5.md`); several parts not wired yet, see the note |
| 2026-11-17 | **DA1 to DA3, deeper analysis:** learned model 2, a stricter typosquat rule, domain-age weights fitted on one sample and confirmed on another, a corpus of 1,640 legitimate deep links for honest false-alarm counts, VirusTotal lookups of a downloaded program's SHA-256 (off by default), risky browser links opened in the sandbox automatically (off by default), established sites never sent to an outside provider, and two tests of the engine itself: how cheaply phishing evades it and how fast the learned model ages (`docs/milestones/DA3.md`) | Verified (measured; acceptance 9 of 9) |
| 2026-11-14 | **AI1 learned model:** `url.learned_domain`, a model fitted to 136,875 real domains, catches phishing domains no rule describes (fresh PhishTank 1.6% to 17.1%, live phishing pages 12.2% to 54.0%, your browsing 0 false alarms of 86); explains which parts of the name pushed it | Verified (`docs/eval/learned-url.md`) |
| 2026-11-14 | **AI1 local brain:** a local model reads an opened page's text, its own code and its screenshot, and an email's request, and answers with quotes; code checks every claim before it counts (business-email compromise, brands in pictures, where a kit sends what you type) | Built and tested against a fake model; off by default, not yet measured |
| 2026-11-14 | **H1 security:** the console has its own session (one-time code, never the API token), an audit log the database refuses to change, secrets under DPAPI (`python -m core.secrets`), hash-locked Python dependencies, sealed quarantine files, site names sealed at rest (ADR-007), an RDAP lookup that cannot be steered to this machine, and a notification when a file or message could not be analysed | Verified (tests) |
| 2026-11-14 | **H1 fewer false alarms:** a popular-domain list (Tranco top 100,000) silences look-alike alarms on brands' own sites; "Was this right?" in the console and "This warning is wrong" on the warning page, counted per rule | Verified (`docs/eval/popular.md`) |
| 2026-11-14 | **H1 deeper analysis:** hiding through `<style>` blocks, active SVG images (`email.svg_active`), links written in PDF page text, forms inside frames and a phone visit for cloaked pages in the detonator | Verified (tests); detonator part built, live run pending |
| 2026-11-11 | **Page detonation (D1):** open a page in a throwaway, locked-down browser container and judge what it shows, not just its address (section 2b) | Verified (on request) |
| 2026-11-11 | **10 page rules:** brand impersonation with a credential or **card** ask (164 brands), password forms posting elsewhere, phishing-kit endpoints (Telegram bots, webhooks, form relays), sign-in pages and brand pages on free hosting or dynamic DNS, anti-analysis code, IP lookups, HTML smuggling, drive-by downloads | Verified |
| 2026-11-11 | **"Open in sandbox" in the console:** the page's route, title, forms, hiding tricks, certificate date and a screenshot, next to the verdict | Verified |
| 2026-11-11 | **Live-page measurement** (`python -m eval.detonate`): real phishing pages and real legitimate pages, split into a tuning half and an untouched test half (section 19) | Verified |
| 2026-11-10 | **False alarms fixed (URL ruleset 1.1.0):** sign-in pages with an encoded return address and share dialogs are no longer flagged; the owner's own browsing went from 9.2% flagged to 0 | Verified |
| 2026-11-10 | **Real-data evaluation (E1):** the URL rules measured on about 300,000 real URLs; the result (2.5% of real phishing caught from the address alone) is what led to D1 | Verified |
| 2026-11-10 | **Unknown macros read as programs:** a bounded VBA evaluator, call-graph analysis, Excel 4.0 macros, VBA stomping (section 5) | Tested |
| 2026-11-10 | **Local AI reviewer for macros** (Ollama, on this computer only, advice that can never decide) (section 11) | Off by default |
| 2026-11-10 | **Go-live safeguards:** installs refuse to run where Windows would not see them, and check Windows' own view afterwards | Verified |
| 2026-11-10 | **Documentation:** this file and [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) | Done |

---

## Capabilities at a glance: what Lynceus can do

**Detect**
- Judge every web page you open in Edge (Chrome expected) and warn before a phishing page; stop known-bad pages before they load.
- Judge every file that lands in Downloads, with no window open.
- Open a suspicious page in a sandboxed browser and read what it really shows: whose brand it wears, what it asks for, where it sends your password, how it hides.
- Read emails (an `.eml`, or a Gmail/Outlook inbox, so far tested against fakes only): sender tricks, authentication failures, hidden and lookalike links, QR codes, dangerous attachments.
- Look inside files: scripts, shortcuts, programs, PDFs, archives, images, Office documents, and unknown macros, by reading their code.
- Match known phishing and malware: OpenPhish and PhishTank lists, local hash lists, optional VirusTotal, urlscan, URLhaus, MalwareBazaar, domain age.

**Investigate and explain**
- One of five verdicts with a 0 to 100 score, a confidence, every reason in plain words, the evidence behind it, MITRE ATT&CK tags, and which source said what.
- An analysis workbench: paste a link, drop a message or a file, or open the page in the sandbox, and see the full anatomy.

**Respond**
- Warning pages, Windows notifications, and reversible quarantine of malicious files and (with a separate permission) messages; nothing is ever deleted; every step audited.

**Protect your privacy**
- Everything runs on this computer; nothing about your browsing, mail or files leaves it unless you turn on a specific provider, and then only a bare domain.

**Measure itself**
- Published, reproducible measurements on synthetic samples and on real data, including the bad numbers.

---

## 1. At a glance

| Lynceus protects | How | Status |
|---|---|---|
| Your browsing (Edge, Chrome) | judges every page you open and shows a warning page before phishing | Verified (Edge); Chrome expected, not tested |
| Your downloads | judges every new file in Downloads, notifies you, offers quarantine | Verified |
| Files you are unsure about | drop them on the Analyze page for a full explanation | Verified |
| Pages you are unsure about | open the page in a throwaway, locked-down browser and judge what it shows | Verified (on request; risky browser links open by themselves if `LYNCEUS_AUTO_DETONATION` is switched on) |
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

## 2b. Page detonation: judging the page, not just the address (D1)

Most real phishing shows nothing in its address (E1: no URL rule fires on 91.2%). The page gives it away. On request, Lynceus opens the page in a throwaway browser container and judges what it shows.

| Feature | What it does | Status |
|---|---|---|
| Throwaway browser | each page gets a fresh Chromium container (Playwright 1.64.1), removed afterwards | Verified |
| Locked down | non-root, Chromium's own sandbox on, seccomp, read-only, no capabilities but one, 1 GB, killed at 32 s, nothing from this computer mounted | Verified (tested) |
| Cannot reach your network | the browser's network has no route out; its only exit is a proxy that accepts public web servers only (no LAN, router, Docker host, cloud metadata, loopback) | Verified (tested) |
| Never interacts | nothing typed, clicked or submitted; downloads cancelled; dialogs dismissed; pop-ups closed | Verified |
| Brand impersonation | a page presenting itself as a listed brand (title, heading) that asks for a password, an account or **card details** on a host the brand does not own (164 brands) | Verified |
| Brand pages on shared hosting | a brand page on S3, Blogspot, a PaaS or dynamic DNS before any form appears (weak alone) | Verified |
| Where your password goes | a password form that posts to another site or a bare IP | Verified |
| Phishing-kit endpoints | a sign-in page that names a Telegram bot, a Discord webhook or a form-relay service | Verified |
| Free-hosting sign-in pages | a sign-in form on pages.dev, workers.dev, web.app, github.io, IPFS gateways, site builders, tunnels | Verified |
| Anti-analysis code | a sign-in page that sets a debugger trap, watches for developer tools, blocks keyboard shortcuts, writes decoded content into itself, or looks up the visitor's IP | Verified |
| HTML smuggling and drive-by downloads | a file built inside the page, or a dangerous file pushed by the page | Verified |
| Landing page | where redirects end is judged by the URL rules too | Verified |
| Screenshot | shown in the console, decoded only inside the parser sandbox, never stored | Verified |
| One verdict | page signals scored with the URL and intelligence signals by the same model; MALICIOUS still needs two independent kinds of evidence | Verified |
| On request only | console "Open in sandbox", `python -m core.cli detonate`, `POST /v1/urls/detonate` (`LYNCEUS_DETONATION=true`) | Verified |
| Automatic opening while browsing or for email links | a second visit can use up one-time links and tells senders your address is live | Not built (D1b, opt-in) |
| Recognising a brand from its picture | a local vision model on the screenshot | Not built (D1b) |

The rules are listed in section 18. Measured on live pages: section 19 and `docs/eval/detonate.md`.

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
| URLhaus | malware URLs | Needs your abuse.ch key (`docs/KEYS.md`); checked live |
| MalwareBazaar | recent malware hashes into the local hash lists | Needs your abuse.ch key; checked live |
| VirusTotal | domain reputation (sends only the registered domain, never for a popular or brand-owned site) and, if `LYNCEUS_FILE_REPUTATION` is switched on, the SHA-256 of a downloaded program | Needs your key; checked live; off until named |
| urlscan.io | domain verdicts (sends only the bare domain) | Needs key, off |
| RDAP domain age | young domains (sends only the registered domain, never for a popular site) | Off by default; no key needed |
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

## 18. Page rules (10)

What the opened page shows (D1). Each gives one reason in plain words; one alone never makes a page MALICIOUS.

| Rule | Fires when |
|---|---|
| Brand impersonation | the page presents itself as a listed brand in its title or headings (not "sign in **with** Google", not a payment or app-store logo) and asks for a password, an account or card details on a host the brand does not own |
| Password sent elsewhere | a password form posts to another site or a bare IP (single sign-on providers and official domains excepted) |
| Phishing-kit endpoint | a page asking for credentials names a Telegram bot, a Discord or Slack webhook or a form-relay service |
| Sign-in page on free hosting | a sign-in or card form on pages.dev, workers.dev, web.app, github.io, IPFS, a site builder, a PaaS, a tunnel or dynamic DNS |
| Brand page on free hosting (weak) | a brand page on such hosting, or on S3 or Blogspot, before any form appears ("View the shared document") |
| Hides from analysis | a sign-in page that sets a debugger trap, watches the window size for developer tools, blocks keyboard shortcuts or writes decoded content into itself |
| Looks up your IP (weak) | a sign-in page that calls an IP-geolocation service (kits use it to hide from scanners) |
| HTML smuggling | the page built a file inside the browser and started its download |
| Drive-by download | the page pushed a dangerous file type by itself |
| Landing address | where the redirects end is judged by the 20 URL rules (except when an official site chose the redirect) |

Deliberately **not** rules: "a password field on an unknown site" and "the page moved to another site" (every login page and every single sign-on would trip them). Brand words: the URL list plus `rules/page/brands.toml` (164 brands).

---

## 19. Quality measurement

| Tool | What it measures |
|---|---|
| `python -m eval` | precision, recall, F1, abstain rate and 95% intervals on the labelled synthetic corpus (dev / holdout / sealed reserve) |
| `python -m eval.realurl` | the URL engine on ~300,000 real URLs (PhiUSIIL, PhishTank, OpenPhish, Tranco, your own browsing locally) |
| `python -m eval.perf` | latency and throughput on this machine |
| `python -m eval.detonate` | page detonation on live phishing and legitimate pages (1,100 pages opened on 2026-11-11; tuning half and test half kept apart; `--rescore` re-judges the kept pages without opening anything) |
| Test suites | 2,540 Python tests, 349 agent tests, 114 + 7 extension tests, 60 + 12 console tests |
| Rule fixtures | every rule has at least one positive and one negative example, enforced by a test |

### The honest results

| Measurement | Result |
|---|---|
| URL rules on synthetic samples | precision 1.000, recall 0.966 |
| Email rules on synthetic samples | precision 1.000, recall 0.973 |
| **URL rules on real phishing (E1, 133,195 URLs)** | **2.5% caught**; 22.9% of OpenPhish's fresh URLs |
| **Live phishing pages, URL rules alone (D1 test half, 118 alive pages)** | 16.9% caught |
| **Live phishing pages, URL rules + the opened page (D1 test half)** | **37.3% caught** (29.1 to 46.3), 9.3% MALICIOUS; 24 of the 44 caught only because of the page |
| Live legitimate pages flagged, URL + page (D1 test half, 186 alive) | 3.8% (7): 6 by the URL rules alone (typosquat, login path), 1 added by the page |
| Real sign-in pages with a password form flagged (D1 test half) | 1 of 26 |
| Real phishing where no URL rule fires at all | 91.2% |
| False alarms on real legitimate URLs (166,265) | 0.3% |
| False alarms on the owner's own browsing | 0 of 87 (after ruleset 1.1.0) |

The synthetic numbers show the rules do what they were written to do. E1 shows the limit of reading an address alone. D1 shows what opening the page adds: on live phishing pages that no list is assumed to know, the share caught more than doubles (16.9% to 37.3%) while the page rules added one false alarm on 186 legitimate pages. About half of the listed phishing pages were already gone or refused the visit when opened, and 63% of the live ones still pass: they show no brand, no form, or something else to a scanner (cloaking). Domain age, visual brand matching and anti-cloaking are next (section 20). Full report: `docs/eval/detonate.md`.

---

## 20. Expected future features (the road ahead)

Ordered by what the measurements say matters most. Each phase is its own milestone with a written plan, approval, tests and a measurement before it counts as done. Sizes are relative (S, M, L, XL). Everything here is **Planned**, not built.

### Next: finish page analysis (D1b)

| Feature | What it adds | Size |
|---|---|---|
| Automatic page detonation (opt-in) | open unknown pages by themselves while you browse and for links in mail, with one-time-link protection (sign-in and reset links skipped) | M |
| Visual brand matching | a local vision model, or image embeddings, reads the screenshot and names the brand a page imitates, even when it is only a picture | M |
| Domain age and certificate transparency | a domain registered or first certified days ago is one of the strongest signs; needs certificate-transparency or newly-registered-domain data | M |
| Anti-cloaking | a phone browser profile, a longer settle, bot-check pages recognised as "hidden", optionally a different exit address | M |
| Frame checking | judge sign-in forms loaded inside frames from another site | S |

### Better decisions

| Feature | What it adds | Size |
|---|---|---|
| Learned scoring | a calibrated model trained on the real E1 and D1 data, with the rules kept as the explanation | M |
| Feedback buttons | "this was right / wrong" in the console and on the warning page; every mistake becomes test data | S |
| Campaign memory and retro-hunt | link related pages, messages and files; when a list learns a URL tomorrow, re-check what you saw yesterday and tell you | M |

### Deeper email analysis

| Feature | What it adds | Size |
|---|---|---|
| Own SPF, DKIM, DMARC and ARC checks | stop trusting the header a receiving server wrote | M |
| Sender relationship history | "this sender has never written to you", a lookalike of a known contact, a hijacked reply chain | M |
| Business-email-compromise intent | the local model reads the request itself (payment change, gift cards, urgency from "the CEO"); advice only | M |
| Current attachment tricks | SVG with scripts, QR codes inside PDFs, OneNote, ISO/IMG/VHD, 7z and RAR, OCR of image-only lures, password-protected archives whose password is in the mail | L |
| Live Gmail and Outlook | run against the real services (today tested against fakes only); the macro reviewer in the mailbox poller | S |
| "Report phishing" | one click from the mailbox into the console | S |

### Deeper file analysis

| Feature | What it adds | Size |
|---|---|---|
| YARA rules | the industry-standard pattern language, with community rule feeds | S |
| Program capabilities | describe what a Windows program can do (capa) | S |
| AMSI provider | see the decoded script and macro calls Windows itself hands to antimalware at run time | M |
| Dynamic detonation of documents | open documents in an instrumented virtual machine and watch what they do | L |
| Real malware test set | measure on real samples kept inside an isolated VM, never on this computer | M |

### Endpoint protection (EDR-lite, no kernel driver)

| Feature | What it adds | Size |
|---|---|---|
| Agent as a Windows service | runs as SYSTEM, survives logoff, harder for malware to stop (changes ADR-016; needs your approval) | M |
| Process, network and script telemetry | Sysmon and ETW: every process with its command line, network connections, DNS, file writes, registry, loaded modules | L |
| Phishing kill-chain detection | the browser downloads a file, it runs, Office starts PowerShell, PowerShell goes to the internet: caught as one story | L |
| Behaviour rules (Sigma) | readable detection rules mapped to MITRE ATT&CK | M |
| Response on the endpoint | stop a process, isolate the computer from the network (Windows Filtering Platform), roll files back from shadow copies | L |
| Password-reuse warning | warn when you type a password you use elsewhere into an unknown site | M |
| Tamper resistance | a watchdog, a locked install folder, signed programs | M |

### Full EDR (needs a company and Microsoft's programs)

| Feature | Why it is separate | Size |
|---|---|---|
| Kernel file-system filter and kernel callbacks | block before a file is written or a process starts; needs a Microsoft-signed driver (EV certificate, attestation) | XL |
| Protected process (ELAM / PPL) | malware cannot stop the agent; needs Microsoft Virus Initiative membership | XL |
| Memory scanning | find code that only exists in memory | L |

### Enterprise platform

| Feature | What it adds | Size |
|---|---|---|
| Central management server | enroll many computers over mutual TLS, push policies, see every alert in one place | XL |
| Single sign-on and roles | SAML/OIDC sign-in, analyst and admin roles, per-component credentials instead of one shared token | L |
| SIEM connectors | Splunk, Microsoft Sentinel, syslog/CEF (today: JSON-lines export) | M |
| Signed builds and auto-update | code signing, signed update packages, a software bill of materials, hash-locked dependencies everywhere | M |
| CI that runs | every change built and tested on a clean machine | S |
| Evidence encryption at rest | ADR-007, unsigned today | M |
| Independent penetration test, SOC 2 / ISO 27001 processes | what buyers ask for | L |

### Targets instead of "perfect"

| Measure | Today | Target |
|---|---|---|
| Real phishing pages caught (live, alive pages) | 37.3% | 85% or more |
| False alarms on legitimate pages | 3.8% (mostly the URL typosquat rule) | 0.1% or less |
| False alarms on your own browsing | 0 of 87 | 0 |
| Real malware caught (files) | not measured | measured on real samples |
