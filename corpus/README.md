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
