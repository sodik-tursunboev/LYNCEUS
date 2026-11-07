# LinkedIn post: Lynceus

Images, in this order: `1-cover.png` (first, it carries the hook), `2-verdict.png`.
Alt text 1: "Lynceus, phishing solution kit. An eye inside a shield, with the pipeline: see, contain, decide, explain, act."
Alt text 2: "The Lynceus console showing a link scored 91 of 100 and marked malicious, with the named signals that explain why."

---

I'm building a phishing detector that sees through the disguise.

**Lynceus**, a local-first Phishing Solution Kit for Windows. (Named after the Argonaut who could see through walls.)

Most phishing tools wait for you to paste a link into a website. Lynceus runs on your PC all day, in the browser, the mailbox and the files you download, and decides before you click.

**Why I think it's strong**

🔍 **It looks inside, not just at names.** Links, emails and files: scripts (VBS, PowerShell), hidden layers, shortcuts, macros, archives. File hashes (SHA-256, SHA-1, MD5) are matched against known-bad lists.
🧱 **Untrusted files are opened only in a sandbox** (AppContainer + Job Object): no network, hard limits.
🧾 **Every verdict shows its work.** A score, named signals mapped to MITRE ATT&CK, the evidence. "Unknown" is never treated as "safe".
↩️ **Responses are reversible.** Quarantine you can undo. Nothing is ever auto-deleted.
🔒 **On-device by default.** No outside service is asked unless you turn it on.

**What is done**

✅ Detection engine and API (Python), Windows agent (.NET), browser extension, desktop console (React + Tauri), per-user MSI installer
✅ 2,300+ automated tests across Python, C# and TypeScript
✅ Gmail and Outlook connectors, read-only by default

**What is not done yet** (I'd rather say it than pretend)
⚠️ The mailbox connectors are tested against fakes, not live accounts
⚠️ The installer is unsigned
⚠️ The evaluation corpus is synthetic, so no real-world accuracy claim yet

Next: live mailbox tests, a signed installer, an evaluation on real data.

If you work in email security or detection engineering, I'd love your feedback.

#cybersecurity #phishing #infosec #python #dotnet #buildinpublic
