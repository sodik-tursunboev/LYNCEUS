# Connect your keys and your Gmail

Four things, in this order: VirusTotal, abuse.ch (URLhaus and MalwareBazaar), Gmail, Outlook (Gmail and Outlook are independent: do the one you use, or both). Each takes a few minutes. Checked against the vendors' documentation on 2026-11-17; nothing here has been run against your real accounts until you do the "Check" step of each part.

**The rules that keep a key safe**

- Keys are typed **hidden** into Lynceus and stored by Windows (DPAPI) in `C:\mirage\secrets.dpapi.json`. Only your Windows user on this computer can read them back.
- A key never goes into `.env`, into code, into git, or into a chat (not even this one). Only settings that are not secret (a list of provider names, a Gmail client ID) go into `.env`.
- Run every command below in a **normal PowerShell** (Start menu, "Windows PowerShell"), not in a terminal inside the Claude app: the app keeps its own private copy of your profile and the key would be stored where Lynceus cannot read it (ADR-024).
- Every command starts from the project folder:

```powershell
cd C:\mirage
```

## 1. VirusTotal (free key)

1. Sign up at <https://www.virustotal.com> (a free account).
2. While signed in, open <https://www.virustotal.com/gui/my-apikey> and copy your API key.
3. Store it. Paste when asked: **nothing appears while you paste, that is normal**. Press Enter.

```powershell
.\.venv\Scripts\python.exe -m core.secrets set virustotal_api_key
```

4. Turn it on, **after step 3** (VirusTotal on without a key makes the core refuse to start). Open `C:\mirage\.env` in Notepad, find the line `LYNCEUS_INTEL_PROVIDERS=openphish,phishtank` and add `,virustotal` at the end of it (no spaces, no quotes). Save.
5. Restart the core (part 5 below).
6. Check:

```powershell
.\.venv\Scripts\python.exe -m core.intel lookup https://example.com/ --ask
```

You should see a line that starts `virustotal  OK`. `ERROR  credentials rejected` means the key was copied wrongly: run step 3 again.

**What it sends:** the registered domain name (`example.com`) of **each site your browser checks that is not an established one**, never a path, a query, a token or an email. Established means Tranco's top 100,000 and a brand's own domains: since DA2 those are not sent at all (before DA2 every site was, google.com included, which was more than "one domain" suggests). VirusTotal's documentation says any indicator queried through its API "will be scanned and added to the VirusTotal dataset, making it accessible to the community", so it is only used for public domains. Domains found in email links are **not** asked about unless you set `LYNCEUS_INTEL_EMAIL_LINKS=true`. The free key is limited to 4 requests a minute and 500 a day and may not be used in commercial products; Lynceus remembers answers for six hours and stays inside those limits. A clean answer never makes a link safe; it only adds evidence.

### 1b. VirusTotal for downloaded files (optional, DA2)

A second, separate switch: for a downloaded **program-like file** (programs, installers, scripts, shortcuts, disk images, archives, macro-enabled Office files; never PDFs, pictures or plain documents) Lynceus asks VirusTotal what its engines say about the file's SHA-256. Many engines flagging it is exact identification (the file is treated as known malware), a few make it SUSPICIOUS, one or two are shown and never enough alone. It needs the VirusTotal key from part 1. Add one line to `C:\mirage\.env`, then restart the core (part 5):

```
LYNCEUS_FILE_REPUTATION=true
```

**What it sends:** the SHA-256 of that file, and nothing else: not the file, its name or its folder. A hash cannot be turned back into a file, but it does tell VirusTotal that this file exists on a computer using your key, and VirusTotal's documentation says a queried indicator is added to its dataset and visible to the community. A file the local known-bad list already knows is not asked about. Every lookup is recorded in the audit log (`file.reputation`, the answer: `report`, `no_report` or `failed`, never the hash). The free key allows 4 requests a minute and 500 a day; past that, or on any failure, the file's verdict is exactly what it would have been without this. To switch it off, remove the line and restart.

## 2. abuse.ch: URLhaus (malware links) and MalwareBazaar (malware file hashes)

1. Go to <https://auth.abuse.ch/> and sign in (Google, GitHub, LinkedIn, X, or an emailed link). Your **Auth-Key** is on your account page there. abuse.ch's pages do not name the exact label, so look for "Auth-Key"; one key is used for both services.
2. Store it (hidden, as above):

```powershell
.\.venv\Scripts\python.exe -m core.secrets set urlhaus_auth_key
```

3. In `.env`, add `,urlhaus` to `LYNCEUS_INTEL_PROVIDERS` (the same line as in part 1). Save, then restart the core (part 5).
4. Check. Both commands only **download** lists; nothing about your files or links is sent. Do not run them more than once every five minutes.

```powershell
.\.venv\Scripts\python.exe -m core.intel sync --feed urlhaus
.\.venv\Scripts\python.exe -m core.intel hashes sync --force
```

You should see `urlhaus ... updated` and `malwarebazaar ... updated`. The core keeps the URLhaus list fresh by itself. The MalwareBazaar hashes are **only** downloaded when you run the second command (each download adds the last 48 hours of new malware hashes to your local list), and the core reads that list when it starts: run the command now and then, and restart the core after. The free service is for fair, non-commercial use.

## 3. Gmail (read-only)

Lynceus reads your mail to check it and never sends, deletes or drafts anything. It asks Google for one permission, `gmail.readonly` ("View your email messages and settings"). Moving a dangerous message out of the inbox is a separate, wider permission you can decide on later (`python -m core.mailbox connect --write`).

You create the connection in **your own** Google Cloud project, so no one else's app ever sees your mail.

1. Open <https://console.cloud.google.com> and sign in with the Google account that owns the mailbox.
2. At the top, open the project picker, choose **New project**, name it `Lynceus`, **Create**, then select it.
3. Menu, **APIs & Services**, **Library**, search **Gmail API**, **Enable**.
4. Menu, **Google Auth platform**. If it says "not configured yet", click **Get started** and fill in: App name `Lynceus`, your email as support email, Next; Audience **External**, Next; your email as contact, Next; agree to the User Data Policy, **Continue**, **Create**.
5. **Audience**, **Test users**, **Add users**: add your own Gmail address, **Save**.
6. **Data Access**, **Add or Remove Scopes**: find `https://www.googleapis.com/auth/gmail.readonly`, tick it, **Update**, **Save**.
7. **Clients**, **Create client**: Application type **Desktop app**, name `Lynceus desktop`, **Create**. Copy the **Client ID** and the **Client secret** shown (you can reopen the client from the Clients list later).
8. Store the secret (hidden):

```powershell
.\.venv\Scripts\python.exe -m core.secrets set gmail_client_secret
```

9. Put the client ID (not secret) in `C:\mirage\.env` as two new lines, no quotes, no spaces around `=`:

```
LYNCEUS_GMAIL_CLIENT_ID=PASTE-YOUR-CLIENT-ID.apps.googleusercontent.com
LYNCEUS_GMAIL_ENABLED=true
```

10. Sign in:

```powershell
.\.venv\Scripts\python.exe -m core.mailbox connect
```

Your browser opens. Choose your Gmail account. Google will say **"Google hasn't verified this app"**: that is expected, it is your own app. Click **Advanced**, **Go to Lynceus (unsafe)**, tick the permission, **Continue**. The window then says you can close it, and PowerShell prints `Connected (read-only)`.
11. Check:

```powershell
.\.venv\Scripts\python.exe -m core.mailbox status
```

You should see `"state": "connected"`. Restart the core (part 5); within a minute the console's **Protection** page shows Gmail with a last-poll time, and new mail appears in the event list.

**The seven-day catch.** Google's documentation says that while an External app is in **Testing**, its sign-in expires after seven days, and `status` then shows `reauth_needed`. Two ways to deal with it:

- Run `connect` again each week (step 10). Nothing is lost.
- Or, once, in the Google Auth platform **Audience** page, click **Publish app**. Google's pages state the seven-day limit only for Testing; a published app that Google has not verified keeps the "hasn't verified" screen and Google caps it at 100 new users, which does not matter for one person. This is the better choice for a mailbox you want checked all the time.

A password change on the Google account, six months without use, or revoking access at <https://myaccount.google.com/permissions> also ends the sign-in; `connect` again fixes it. To remove it yourself: `.\.venv\Scripts\python.exe -m core.mailbox disconnect`.

## 4. Outlook / Microsoft 365 mail (read-only)

Same idea as Gmail: you register a small app of your own with Microsoft, so no one else's app ever sees your mail. It asks for one permission, Microsoft Graph **Mail.Read** ("Read user mail"), which Microsoft lists as needing no administrator consent and as available to personal accounts (outlook.com, hotmail.com, live.com) and work or school accounts. There is no secret to store for this one.

Microsoft's pages list an Azure account as the prerequisite for registering an app and do not say whether the free sign-up asks for a card. If it does, that is Microsoft's own identity check on their page; you decide whether to go on.

1. Open <https://entra.microsoft.com> and sign in with the Microsoft account that owns the mailbox.
2. **Entra ID**, **App registrations**, **New registration**.
3. Name: `Lynceus`. Supported account types: the option that includes **personal Microsoft accounts** (its wording differs slightly between portal versions). Leave Redirect URI empty. **Register**.
4. On the app's **Overview** page copy the **Application (client) ID**.
5. **Authentication**, **Add a platform**, **Mobile and desktop applications**, enter exactly `http://localhost`, **Configure**. Then, still under **Authentication**, **Advanced settings**, **Allow public client flows**: **Yes**, **Save**. (Microsoft recommends this for desktop apps; its page does not say the sign-in fails without it.)
6. **API permissions**, **Add a permission**, **Microsoft Graph**, **Delegated permissions**, tick **Mail.Read**, **Add permissions**.
7. In `C:\mirage\.env` add (the client ID is not secret; no quotes, no spaces around `=`):

```
LYNCEUS_OUTLOOK_CLIENT_ID=PASTE-THE-APPLICATION-CLIENT-ID
LYNCEUS_OUTLOOK_ENABLED=true
```

8. Sign in:

```powershell
.\.venv\Scripts\python.exe -m core.mailbox connect --provider outlook
```

Your browser opens: choose the account, accept "Read your mail", and PowerShell prints `Connected (read-only)`. The default `LYNCEUS_OUTLOOK_TENANT=common` works for personal and work accounts.
9. Check:

```powershell
.\.venv\Scripts\python.exe -m core.mailbox status --provider outlook
```

You should see `"state": "connected"`. Restart the core (part 5). Microsoft's page says refresh tokens for desktop apps have no specified lifetime but can expire or be revoked; if `status` ever shows `reauth_needed`, run step 8 again. To remove it: `.\.venv\Scripts\python.exe -m core.mailbox disconnect --provider outlook`, then remove the app's access on your Microsoft account's app permissions page.

## 5. Restart the core (after any change to `.env` or a stored key)

The agent starts the core again by itself a few seconds after it stops, reading `.env` and your keys fresh:

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'core\.api\.app:create_app' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

If the console shows "the core is not running" for more than a minute, a line in `.env` is wrong (a missing key makes the core refuse to start, by design); run `.\.venv\Scripts\python.exe -m core.intel status` to see the message.

## What leaves this computer

| Part | Sent | Never sent |
|---|---|---|
| VirusTotal (domains) | the registered domain of each checked site that is not established (not in Tranco's top 100,000, not a brand's own domain) | the URL, path, query, token, email text, files |
| VirusTotal (files, only if you switch it on) | the SHA-256 of a downloaded program-like file | the file, its name, its folder; PDFs, pictures and documents are never asked |
| abuse.ch | nothing (a download of their lists, with your key in the address) | anything about your links or files |
| Gmail, Outlook | nothing: Google or Microsoft gives Lynceus your messages, they are checked here | message text goes nowhere; only if you also turn on `LYNCEUS_INTEL_EMAIL_LINKS=true` are the **domains** of links in mail asked about at VirusTotal |

To remove a key: `.\.venv\Scripts\python.exe -m core.secrets remove virustotal_api_key` (and take `,virustotal` out of `.env`). `.\.venv\Scripts\python.exe -m core.secrets list` shows the names stored, never the values.
