# UI2: a production-grade console

**Asked by the owner (2026-11-16):** "fix the Lynceus app itself, design issues fully, and upgrade the design to the next level, production ready. Add new tabs, fix overlays, text and icon issues." This plan needs approval before any code (CLAUDE.md, "How to work").

**Decisions (owner, 2026-11-16):** plan approved as written; all three new tabs (Protection, Feedback, Guide).

**Status (2026-11-16): built and verified; pending your review.** Results at the end.

## What the review found

Every page of the console (sign-in, Overview, Analyze empty, a link analysed, an email intake, Events, an event, Responses, Allow list, Audit log) was opened against a real core with a throwaway SQLite database and made-up `.test` samples, at 1440, 1024, 768 and 390 px wide, dark and light, in headless Edge. Each page was photographed and measured by script (sideways overflow, text spilling out of its box, overlapping text, contrast, text size, target size, unnamed controls, console errors), then looked at.

**Bugs and overlaps**

1. **Phone: half the console is out of reach.** Below 860 px the sidebar becomes one sideways strip; at 390 px only Overview, Analyze and Events fit. Responses, Allow list and Audit log are off screen, with nothing showing they exist.
2. **Phone: the link result is 497 px wide on a 390 px screen.** The engine and ruleset line (a long version string) cannot wrap, so the whole page scrolls sideways.
3. **Phone: the Events table hides most of itself.** Only When, Kind and Where from fit; verdict, score, signs and response are off to the side, and each row is two to three lines tall.
4. **Event page, 1080 px and below:** the risk ring stacks above the text and leaves half the verdict panel empty; the small kind icon in the header line is left alone on its own line.
5. **Overview tiles:** with five tiles in a row the labels wrap to two or three lines, and "not set up" (Mail) breaks across two lines in the large figure font.

**Text**

6. **Too small to read comfortably:** the brand subtitle (10 px), every verdict and state badge (10.5 px), table headers (11 px), the ring's caption (10.5 px).
7. **Rule ids instead of words:** the overview's detection feed shows `url.brand_in_subdomain, url.learned_domain`; the same link analysed five times is listed five times.
8. **Spacing:** "Open in sandbox" sits flush against the paragraph above it.

**Targets and icons**

9. **Small targets:** standalone links such as "All events" and the verdict badges that link to an event are 21 px tall (the minimum is 24 px).
10. **Icon alignment:** an icon that wraps away from its text (item 4); every icon-and-text pair is to be checked by script, not by eye.

**Tooling**

11. `tools/shoot.mjs` still signs in with `#token=`, which H1 removed: today it only photographs the sign-in page.

**Missing**

12. The theme follows Windows only; there is no switch.
13. The core already reports things no page shows in full: the threat-intelligence providers and feeds (`GET /v1/intel/health`: what each provider sends, whether it is usable, how old each feed is), the mailbox's last check and counts (`GET /v1/mailbox/status`), and the per-rule feedback beyond the top eight (`GET /v1/feedback/rules`).

Contrast was measured on every text element of every page in both themes: no pair below 4.5:1 once gradients are accounted for, so colours stay.

## What UI2 builds

**Three new tabs** (existing core endpoints only; nothing changes in the core):

- **Protection** (`#/protection`): the state of every guard in one place. The analysis engine; the mailbox (state, last check, messages read, flagged); each threat-intelligence provider (what it sends, usable or not, circuit-breaker state) and each feed (entries, age, stale or fresh); how responses are decided. Anything off is said in words, with what turns it on.
- **Feedback** (`#/feedback`): every rule you have judged, with false alarms, right and missed, noisiest first, and the recent events each rule fired on (from the last 200 events). The overview keeps its short list and links here.
- **Guide** (`#/guide`): what each of the five verdicts means and what to do, what each response does and how to undo it, what never leaves this computer, and the keyboard shortcuts. The words come from the same tables the badges use (`theme.ts`, `policy.ts`), so they cannot drift apart.

**Fixes and upgrades**

- **Navigation:** grouped sidebar (Monitor: Overview, Events, Responses; Investigate: Analyze; Manage: Allow list, Feedback, Audit log; Help: Protection, Guide) with counts where they matter (waiting decisions). On a phone: a top bar with the brand, core status and a **Menu** button that opens every page as a full list (a real button with `aria-expanded`, closes on Escape and on choosing a page).
- **Theme switch:** System, Dark, Light, in the sidebar; the choice is kept in this browser (`localStorage`, the word only) and applied before the first paint, so there is no flash.
- **Keyboard:** `g` then a letter goes to a page (`g o` Overview, `g a` Analyze, `g e` Events…); `/` focuses the search on Events and the link box on Analyze; `?` opens the Guide. Never while typing in a field.
- **Events:** search box (host, rule, kind), kind filter beside the verdict filter, and on narrow screens each event becomes a card with every column labelled, instead of a table cut off at the side.
- **Overview:** tiles that fit (four figures plus one status line), the feed in words ("brand in subdomain") with identical repeats collapsed into one row with a count.
- **Type scale:** nothing below 12 px; badges 12 px, table headers 12 px, captions 12 px.
- **Targets:** every standalone control at least 24 px tall; wrapping text never strands an icon.
- **Wrapping:** long hashes, versions and hosts wrap or truncate with the full value in a tooltip and a copy button; no page scrolls sideways at 390 px.
- **Event page:** the ring stays beside the text down to 720 px.
- **Tooling:** `tools/shoot.mjs` is replaced by **`tools/audit.mjs`**: it starts a throwaway core on SQLite with a random token, fills it with made-up `.test` samples through the real API, walks every page at four widths in both themes, saves the screenshots, prints every overflow, overlap, small text, small target, unnamed control, contrast failure and console error, and stops the core. It ends with `AUDIT CLEAN` only when there is nothing to report. It can run before every release.

## Security and privacy

No new permission, dependency, endpoint or outside request. The content security policy stays as it is (no inline script or style: the existing policy test that bans `style={…}` and injected markup keeps passing, so bars and rings stay SVG attributes). The theme choice is the only new stored value: one word in `localStorage`, never the session. The audit tool talks only to the core it started on 127.0.0.1, with a random token it does not print, and deletes its database when done.

## Acceptance (each one checked by a command; ledger in `GATES.md`)

1. Console unit tests, type check and build pass, with new tests for the theme choice, the keyboard shortcuts, collapsing repeats and the rule words.
2. `node tools/audit.mjs` prints `AUDIT CLEAN`: every page (the ten above plus the three new tabs and the phone menu) at 1440, 1024, 768 and 390 px, dark and light, with no sideways overflow, no text out of its box, no overlapping text, no text under 12 px, no standalone target under 24 px, no unnamed control, no contrast pair under 4.5:1, no console error. The same tool run on today's console must fail (proof that it can).
3. The new tabs show the core's real data: Protection lists exactly the providers and feeds `/v1/intel/health` returns; Feedback's counts equal `/v1/feedback/rules`; the Guide names all five verdicts and every response.
4. At 390 px every page is reachable from the menu; the menu opens, closes on Escape and moves focus correctly.
5. The theme switch overrides Windows and survives a reload; System follows Windows again.
6. `npm run test:e2e` (real agent, real core, real Edge) still passes unchanged.
7. Screenshots of every page at 1440 and 390 px in both themes looked at one by one after the fixes (manual; recorded here).

## Not in UI2

No change to verdicts, scoring, responses or any core endpoint. No new outside request. Not tested with a screen reader, Chrome, Firefox or Safari (as in UI1); the audit runs in Edge.

## Results (2026-11-16)

| Check | Result |
|---|---|
| The audit on the console as it was (`node tools/audit.mjs --at 9ba4f2c --expect-findings`) | **894 findings** before any fix: 448 texts under 12 px, 260 elements off the side of a phone screen, 136 controls under 24 px, 8 overlapping texts (two real overlaps, the overview feed's rule list running under the verdict badge at 390 px, a fault the first look missed; counted four times because the old console showed its overview for the tabs it did not have yet), 6 icons left alone above their text (the event page's header), the link result scrolling sideways at 390 px, no phone menu, no theme switch, no new tabs |
| The same audit now (`node tools/audit.mjs`) | **AUDIT CLEAN**: 108 screenshots (12 pages plus sign-in at 1440, 1024, 768 and 390 px, dark and light, plus the open phone menu at 768 and 390), nothing to report |
| New tabs (`--only tabs`) | **TABS MATCH CORE**: Protection lists exactly the providers and feeds `/v1/intel/health` reports, with the same usable state and entry counts; Feedback's counts equal `/v1/feedback/rules` rule by rule; the Guide explains all five verdicts and all five responses |
| Phone menu (`--only menu`) | **MENU REACHES EVERY PAGE**: at 390 px all 9 pages open from the menu, it says it is open, closes when a page is chosen and on Escape, and gives the focus back to the button |
| Theme switch (`--only theme`) | **THEME SWITCH HOLDS**: Light beats a dark Windows setting and survives a reload, System follows Windows again (both ways), Dark beats a light setting, the choice is marked as chosen |
| Console unit tests, type check, build | 80 tests (71 before): new ones for the theme choice, the keyboard shortcuts, collapsing repeats and rule words, and a stricter storage rule (only `prefs.ts` and `static/theme.js` may touch `localStorage`, for one key, and `theme.js` only reads it). Bundle 405 KB (365 KB before; most of it the 14 new icons in three weights), stylesheet 47 KB |
| End to end (`npm run test:e2e`: real agent, real core, real Edge) | **12 passed**, unchanged: every label, route and text it relies on is kept |
| Core and rules | no file changed under `core/` or `rules/` (checked against `9ba4f2c`) |
| Looked at | after the fixes, every page at 1440 and 390 px in both themes, in contact sheets; 16 screenshots one by one at full size. This found five faults no measurement catches, all fixed: the brand line breaking onto a second line, status chips stretched across the panel, "a email", a two-line shortcut hint, and phone event cards about 380 px tall each (now about 200) |

**The one exception to "nothing is stored":** the console's source test used to ban `localStorage` everywhere. UI2 allows it in exactly one module and the boot script, for the key `lynceus.theme` holding `dark` or `light` (System removes it); the test enforces that. The session itself stays in `sessionStorage`, as before.

**Not verified:** a screen reader; Chrome, Firefox and Safari; a real phone (the phone widths are Edge's emulation). The scroll padding that keeps a focused heading clear of the phone's top bar is a precaution: no case was found where the heading was hidden without it; the audit's check for it was shown to fire when a focused heading is placed under the bar.
