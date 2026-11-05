# corpus/

`manifest.jsonl`: one labelled URL per line, 253 samples. URLs are inert strings: nothing is ever fetched.

| Field | Meaning |
|---|---|
| `id`, `value`, `kind` | sample id and the URL string (`kind` is always `url` for now) |
| `label` | `malicious` or `benign` (ground truth by the author) |
| `category` | what the sample exercises, e.g. `punycode_homograph`, `benign_idn` |
| `origin` | `synthetic`, or `public_real` (a real public URL string, benign only) |
| `source`, `notes` | provenance and a one-line reason |
| `split` | `dev`, `holdout` or `reserve` |

## Rules (enforced when the manifest loads)
- Malicious samples are always synthetic. Every host in them, including a host hidden in a percent-encoded, double-encoded or base64 redirect parameter, is unregisterable (`.test`, `.invalid`, `.example`, `example.com/.org/.net`, RFC 5737/3849 addresses). Lookalikes of real brands sit on `.test`. The check uses the browser's view of the host (WHATWG), not `urllib`'s.
- `public_real` URLs are benign hard negatives only (homepages and login pages of well-known services, no personal data). The URL string is a fact; the official-domain assumption is unverified.
- No phishing-feed URLs, ever. Anything from an authorized external dataset stays outside git.

## Splits
- `dev` (150): tune rules against it.
- `holdout` (49): report only. Run it once at the end of the rules work and record the numbers; never tune on it.
- `reserve` (54): sealed. The eval CLI cannot select it. If a holdout failure drives a fix, those samples move to `dev` and a new holdout is drawn from reserve.
- `pins.txt` pins the hash of the holdout and reserve lines; a test fails if either changes. After a deliberate change, say why in the commit and run `python -m eval.corpus`.

## Limits
- Samples come from seeded templates, and the split is stratified within each template group. The holdout therefore tests generalization across brands and variants, not unseen attack styles, and its size (49) gives wide confidence intervals.
- Synthetic positives measure rule correctness, not the real-world detection rate.
- Shorteners are labelled by assumption (the destination is hypothetical) and are indistinguishable without resolving; expect abstains.
- Brand-adjacent benign samples (`benign_brand_adjacent`) are author-labelled and deliberately hard.

---

## mail/ (M2)
`mail/manifest.jsonl` lists 180 raw messages (`*.eml`, CRLF, never converted: `.gitattributes` marks them `-text`). Fields: `id`, `file`, `file_sha256` (checked on load), `label`, `category`, `origin`, `source`, `notes`, `split`. Splits: dev 119 (74 malicious, 45 benign), holdout 35, reserve 26; `mail/pins.txt` pins holdout and reserve (`python -m eval.corpus corpus/mail/manifest.jsonl`). Ids: `m-*` (120, message structure and links), `m2b-*` (40, attachments: zip/tar, PDF, QR image, HTML smuggling; written while the attachment rules were being built and **all dev**), `m2c-*` (20, the same kinds, written blind: **no result was looked at** and no rule had been run on them when they were pinned (only the parser, for validity); they make up the attachment half of the holdout and reserve). Categories include brand-link phish, credential forms, hidden links, link-text mismatch, executable / double-extension / RTL / macro / HTML attachments, type mismatch, spoofed sender with failed authentication, and Polish bank and parcel lures; benign ones include newsletters, threads, calendar invites, official brand mail, lists, a malformed message and Polish mail.

Messages are inert text: nothing is sent, opened or fetched. Rules enforced when the manifest loads:
- A message may be at most 1 MiB and must match its recorded hash.
- In a synthetic message every **destination** (an `href`, `src` or `action`, a URL in a plain-text part or a header, an address domain) is an unregisterable name (`.test`, `.invalid`, `.example`, reserved ranges). A real brand domain may only be **shown** as HTML text (`<a href="https://evil.test/">https://www.paypal.com/login</a>` is the attack being modelled), never be a destination.
- `public_real` messages are benign only, documented, and the only ones that may name real hosts.
- Attachments are small inert byte strings with the right magic number (`MZ`, `%PDF-`, `PK`); none is executable. Archive "bombs" are zip or gzip files of a few hundred KB that *declare* 300 MiB; PDFs are hand-written text with a JavaScript or Launch entry that nothing ever runs; QR images are generated and point at unregisterable names.

Run: `python -m eval --kind mail` (dev), `--split holdout` (explicit, logged in `docs/eval/mail_holdout_runs.md`). The same caveats as the URL corpus apply, stronger: the same author wrote the messages and the rules, so results measure rule correctness, not detection of real phishing.
