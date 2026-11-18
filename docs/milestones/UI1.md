# UI1: the analysis workbench and the new console design

**Status (2026-11-06): built and verified; pending your review.** You asked for a real phishing-analysis interface with icons (the Argus pack or one from the internet) and a design to match. Nothing was downloaded: the icons come from the Phosphor set already inside your Argus HUD.

## What you get

- **Analyze** (new, `#/analyze`): paste a link, drop an `.eml` message, or drop any file. Lynceus analyses it with its own rules, in its sandbox, on this computer, and shows an investigation view:
  - a **risk ring** and a plain-language verdict (what it means and what to do), confidence, recommended response;
  - **Why**: every sign that fired, strongest first, with its category icon, rule id, description, ATT&CK technique and weight;
  - for a link, the **anatomy of the link**: scheme, user name (the `www.paypal.com@` trick shown in red), subdomain, the **owner** (the registered domain, highlighted, "the browser will connect to …"), suffix, port, path, query, with a legend and the parser's flags in words;
  - for an email, the **message summary**, every **link inside** (host, verdict, score, signs, notes such as "hidden from the reader" or "only some mail programs show it"), **attachments and contents**;
  - **evidence** with copyable hashes, **outside opinions** (empty and said so when the setting is offline), engine and ruleset versions, and a link to the stored event.
  - Made-up example links (reserved `.test` names, analysed offline, never opened) to try it at once; this session's analyses can be reopened.
- **Redesign of every page** in the Argus cockpit spirit: near-black teal ground with a faint grid, thin cyan-edged panels, a sidebar with icon navigation and live core status, stat tiles, verdict distribution, detection feed, restyled Events, Event detail, Responses, Allow list, Audit log and sign-in. A light theme follows the operating system setting. On a phone-width screen the sidebar becomes a scrolling top bar.
- **Icons**: 77 Phosphor icons in three weights (regular, duotone, fill), drawn as inline SVG: no icon font, no request. Argus rules kept: regular by default, duotone for the active item.
- **Fonts**: Space Grotesk, Manrope and JetBrains Mono, served from the console's own folder (about 90 KB).
- Licences and credits: `console/THIRD_PARTY.md` (Phosphor: MIT; the fonts: SIL OFL 1.1).

## One change to the core

`POST /v1/urls/analyze` now also returns `anatomy`: how the URL splits into parts (scheme, user name, subdomain, registered domain, public suffix, port, path, query, fragment). Only the server has the Public Suffix List, so only it can say which part is the owner. The password is never included. Nothing about it is logged or stored. It is additive: existing callers are unaffected. Tested in `tests/unit/test_api.py`; `docs/openapi.json` regenerated.

## How it was checked

| Check | Result |
|---|---|
| Console unit tests | 56 (was 26): the URL anatomy, the ring and bands, counts and ordering, sizes and limits, pasted-text detection, SHA-256 against a known vector, UTC time handling, every icon the design refers to exists, every verdict has words and is never styled safe when it is UNKNOWN or ERROR, hostile text is escaped, the policy test that bans inline styles and markup injection still passes |
| Type check, build | clean; bundle 350 KB minified |
| End-to-end in real Edge (real agent, real core) | see the results block at the end |
| Screenshots in headless Edge at 1440 px and 390 px (all pages, a link, an email and a file analysed) | reviewed one by one; three layout flaws found and fixed (stat tiles wrapping, an anatomy line breaking mid-word, a lopsided legend) |
| A real bug found by looking | timestamps came without a time zone and were read as local time ("1 h ago" for something just created); fixed and tested |
| Robustness | content never depends on an animation to be visible (found when the browser pane was not painting); the ring fills from a timer |
| Contrast | every text and state colour pair is at least 4.5:1 in both themes (computed, not eyeballed); the one light-theme pair that was 4.16 was darkened |
| Keyboard and assistive technology | all controls are real buttons, links, tabs or form fields with labels; visible focus ring; a skip link; icons are hidden from screen readers unless they carry meaning; state is always icon plus words plus colour; reduced-motion and forced-colours are handled. **Not tested with a screen reader.** |

## Security and privacy

No new permission, dependency or outside request. The content security policy is unchanged and still holds: no inline script or style, no external file; the policy test that bans `dangerouslySetInnerHTML`, `style={…}` and the rest still passes, so bar widths and the ring are SVG attributes. Files and messages are read in the browser and sent to the core over loopback with the token, exactly as the agent sends them; they are not stored by the console. Analyses from this page are recorded as ordinary events (source API), like any other call to the analyze endpoints.

## Not done, and limits

- **Not verified:** a screen reader, Chrome, Firefox, Safari. The light theme was reviewed in a screenshot (the link analysis page) and by contrast numbers, not page by page.
- Pasted message source is re-encoded as UTF-8: a message with unusual line endings or encodings may analyse slightly differently from the original file. Dropping the `.eml` file is exact.
- Files over 16 MB and messages over 10 MB are refused with an explanation (the core's own limits); a file's metadata-only check is not offered from this page.
- History on the page lasts for the session only.
- Regenerating the icon set needs a copy of `phosphor-svelte` (default: the Argus HUD's): `node tools/make-icons.mjs`. The generated file is committed, so nothing else needs it.
- Review screenshots: `node tools/shoot.mjs` (replaced in UI2 by `node tools/audit.mjs`, which starts its own throwaway core and also measures each page).

## Results (2026-11-06)

- `cd console && npm test`: 56 passed. `npx tsc --noEmit` and `npm run build`: clean.
- `npm run test:e2e` (real agent, real core, real Edge, against this redesign): **12 passed** (flag, approve, quarantine, audit, restore, allow list, a failed action, sign-out). The test needed no change: every label, route and text it relies on is kept.
- `tests/unit/test_api.py`: 41 passed, including the new `anatomy` test.
- Screenshots reviewed: dark at 1440 px (overview, analyze empty, link malicious, link with `@`, events, event detail, responses, allow list, audit log, email intake, email result, file result), dark at 390 px, light theme at 1440 px. No console errors in any run.