// The console's design audit (UI2). Starts a throwaway core on SQLite with a random token, fills it with made-up
// samples through the real API (.test links, generated PDFs, the synthetic mail corpus), then walks every page at
// four widths in dark and light in headless Edge. It saves a screenshot of each and reports every layout fault it
// can measure: sideways overflow, text outside its box, overlapping text, an icon left alone on its own line, text
// under 12 px, a standalone control under 24 px, an unnamed control, a contrast pair under 4.5:1, a console error.
// It also checks that the new tabs show what the core reports, that the phone menu reaches every page, and that the
// theme switch holds. It ends with AUDIT CLEAN only when there is nothing to report.
//
//   node tools/audit.mjs                       everything (about four minutes)
//   node tools/audit.mjs --only tabs|menu|theme
//   node tools/audit.mjs --at <commit> --expect-findings   the same audit on the console built from that commit;
//                                              succeeds only if it finds faults (the negative control)
//   --out <dir>   where the screenshots go (default: a new temporary folder, printed)
//
// Needs: the repository's .venv (python tasks.py deps), Microsoft Edge, and `npm ci` in console/.
// Talks only to the core it started on 127.0.0.1; the token is random and never printed.
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import puppeteer from "puppeteer-core";

const CONSOLE = resolve(import.meta.dirname, "..");
const REPO = resolve(CONSOLE, "..");
const PY = join(REPO, ".venv", "Scripts", "python.exe");
const EDGE = ["C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"].find(existsSync);

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const only = opt("--only");
const at = opt("--at");
const expectFindings = args.includes("--expect-findings");
if (only && !["tabs", "menu", "theme"].includes(only)) throw new Error("--only takes tabs, menu or theme");
if (expectFindings && !at) throw new Error("--expect-findings needs --at <commit>");
for (const f of [PY, EDGE]) if (!f || !existsSync(f)) throw new Error("missing: " + (f ?? "Microsoft Edge"));

const work = mkdtempSync(join(tmpdir(), "lynceus-audit-"));
const out = opt("--out") ?? join(work, "shots");
mkdirSync(out, { recursive: true });
const TOKEN = "audit-" + randomBytes(24).toString("base64url");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const findings = [];
const fault = (where, what) => { findings.push(`${where}: ${what}`); };

// ---- the console under test ------------------------------------------------------------------------------------

function consoleDir() {
  if (!at) {
    if (!existsSync(join(CONSOLE, "dist", "index.html"))) throw new Error("build the console first (node build.mjs)");
    return join(CONSOLE, "dist");
  }
  if (!/^[0-9a-f]{7,40}$/.test(at)) throw new Error("--at takes a commit id");
  const tar = join(work, "old.tar");
  execFileSync("git", ["-C", REPO, "archive", "--format=tar", "-o", tar, at, "console"]);
  execFileSync("tar", ["-xf", tar, "-C", work]);
  const old = join(work, "console");
  symlinkSync(join(CONSOLE, "node_modules"), join(old, "node_modules"), "junction");
  execFileSync(process.execPath, ["build.mjs"], { cwd: old, stdio: "ignore" });
  return join(old, "dist");
}

// ---- a throwaway core ------------------------------------------------------------------------------------------

const freePort = () => new Promise((res) => { const s = createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
let core;
let base;

async function startCore(dist) {
  const db = join(work, "audit.db").replaceAll("\\", "/");
  execFileSync(PY, ["-c", `from sqlalchemy import create_engine\nfrom core.db import models as db\ndb.Base.metadata.create_all(create_engine('sqlite:///${db}'))`], { cwd: REPO });
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  const env = { ...process.env, LYNCEUS_API_TOKEN: TOKEN, LYNCEUS_DATABASE_URL: `sqlite:///${db}`, LYNCEUS_CONSOLE_DIR: dist, LYNCEUS_DETONATION: "false" };
  core = spawn(PY, ["-m", "uvicorn", "core.api.app:create_app", "--factory", "--host", "127.0.0.1", "--port", String(port), "--no-access-log", "--no-server-header"], { cwd: REPO, env, windowsHide: true, stdio: "ignore" });
  for (let i = 0; i < 300; i++) {
    try { if ((await fetch(`${base}/health`)).ok) return; } catch { /* not yet */ }
    await sleep(200);
  }
  throw new Error("the core did not start");
}

function stopCore() {
  if (core?.pid) try { execFileSync("taskkill", ["/PID", String(core.pid), "/T", "/F"], { stdio: "ignore" }); } catch { /* gone */ }
}

const call = async (method, path, body, headers = {}) => {
  const raw = body instanceof Uint8Array;
  const r = await fetch(base + path, {
    method, headers: { Authorization: `Bearer ${TOKEN}`, ...(body === undefined ? {} : { "Content-Type": raw ? "application/octet-stream" : "application/json" }), ...headers },
    body: body === undefined ? undefined : raw ? body : JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status}`);
  return r.json();
};

/** Made-up samples only: .test links, PDFs generated here, the repository's synthetic mail corpus. */
async function seed() {
  const urls = [
    "https://paypal.com.secure-login.account-verify.test/signin?email=jane%40example.test",
    "https://xn--pypal-4ve.test/verify?email=jane%40example.test",
    "https://www.paypal.com@account-check.test/login.php",
    "https://microsoft-office365-login.test/owa/auth.html",
    "http://192.0.2.44/wp-admin/bank/login.php",
    "https://appleid.apple.com.verify-account.test/",
    "https://docs-share.test/file/invoice-2026.html",
    "https://www.google.com/url?q=https://example.org/page",
    "https://www.microsoft.com/",
    "https://login-dhl-parcel.test:8443/track?id=PL123",
  ];
  for (const url of urls) await call("POST", "/v1/urls/analyze", { url });
  for (let i = 0; i < 2; i++) await call("POST", "/v1/urls/analyze", { url: urls[0] }); // a repeat, to be collapsed
  const samples = join(work, "samples");
  mkdirSync(samples);
  execFileSync(PY, ["-c",
    "import sys\nsys.path[:0] = ['tests', 'core/sandbox/guest']\nimport filehelp as fh\n" +
    "bad = fh.make_pdf('/OpenAction 4 0 R', ['<< /S /Launch /F (cmd.exe) >>', '<< /S /URI /URI (https://paypal-login.test/login.php) >>'])\n" +
    `for n in range(6):\n    open(r'${samples}\\\\scan-%d.pdf' % n, 'wb').write(bad + b'\\n%%variant %d\\n' % n)\n`,
  ], { cwd: REPO });
  for (const name of readdirSync(samples)) {
    const bytes = new Uint8Array(readFileSync(join(samples, name)));
    const sha = Buffer.from(await crypto.subtle.digest("SHA-256", bytes)).toString("hex");
    await call("POST", "/v1/files/analyze", bytes, { "X-Lynceus-Name": name, "X-Lynceus-Sha256": sha, "X-Lynceus-File-Id": randomBytes(16).toString("hex") });
  }
  const mail = join(REPO, "corpus", "mail");
  const emls = existsSync(mail) ? readdirSync(mail, { recursive: true }).filter((f) => String(f).endsWith(".eml")).sort().slice(0, 3) : [];
  for (const f of emls) {
    await fetch(`${base}/v1/emails/analyze`, { method: "POST", headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "message/rfc822" }, body: readFileSync(join(mail, String(f))) });
  }
  const pending = (await call("GET", "/v1/actions?limit=50")).filter((a) => a.state === "PENDING");
  if (pending.length >= 4) {
    await call("POST", `/v1/actions/${pending[0].id}/approve`);
    await call("POST", `/v1/actions/${pending[1].id}/dismiss`);
    await call("POST", "/v1/allowlist", { sha256: pending[2].sha256, days: 30 });
  }
  const flagged = (await call("GET", "/v1/events?limit=50")).filter((e) => e.state === "MALICIOUS" || e.state === "SUSPICIOUS");
  if (flagged.length >= 3) {
    await call("POST", `/v1/events/${flagged[0].id}/feedback`, { label: "false_alarm" });
    await call("POST", `/v1/events/${flagged[1].id}/feedback`, { label: "correct" });
    await call("POST", `/v1/events/${flagged[2].id}/feedback`, { label: "false_alarm" });
  }
}

// ---- what is measured on each page (runs in the page) ------------------------------------------------------------

function measure() {
  const vw = document.documentElement.clientWidth;
  const hidden = (el) => !!el.closest("details:not([open]) > :not(summary), [hidden], [inert]");
  const vis = (el) => { const cs = getComputedStyle(el); const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 && cs.visibility !== "hidden" && +cs.opacity !== 0 && !hidden(el); };
  const name = (el) => `${el.tagName.toLowerCase()}${typeof el.className === "string" && el.className.trim() ? "." + el.className.trim().split(/\s+/).slice(0, 2).join(".") : ""} "${(el.textContent || "").trim().replace(/\s+/g, " ").slice(0, 36)}"`;
  const f = [];
  // where the page left the focus (a result heading, a jump target) must not sit under a bar pinned to the top
  const focused = document.activeElement;
  if (focused && focused !== document.body && focused.closest("main")) {
    const fr = focused.getBoundingClientRect();
    for (const bar of document.querySelectorAll("body *")) {
      const pos = getComputedStyle(bar).position;
      if ((pos !== "sticky" && pos !== "fixed") || bar.contains(focused)) continue;
      const br = bar.getBoundingClientRect();
      if (br.height > 0 && br.top <= 0 && fr.top < br.bottom - 2 && fr.bottom > br.top && Math.min(fr.right, br.right) > Math.max(fr.left, br.left)) f.push(`the focused element is under a pinned bar: ${name(focused)}`);
    }
  }
  // the rest is measured on the page's own layout, from the top (content scrolled under a pinned bar is not a fault)
  window.scrollTo({ top: 0, left: 0, behavior: "instant" });
  const all = [...document.body.querySelectorAll("*")].filter(vis);
  const own = (el) => [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
  if (document.documentElement.scrollWidth > vw + 1) f.push(`the page scrolls sideways (${document.documentElement.scrollWidth} px on ${vw} px)`);
  const scrolls = (el) => { for (let e = el.parentElement; e; e = e.parentElement) { const o = getComputedStyle(e).overflowX; if (o !== "visible") return true; } return false; };
  for (const el of all) {
    const r = el.getBoundingClientRect();
    if ((r.right > vw + 1 || r.left < -1) && !el.closest(".skip") && !scrolls(el)) f.push(`off the side of the screen: ${name(el)}`);
    if (own(el) && el.clientWidth > 0 && el.scrollWidth > el.clientWidth + 1 && getComputedStyle(el).overflowX === "visible" && getComputedStyle(el).display !== "inline") f.push(`text out of its box: ${name(el)} (${el.scrollWidth} > ${el.clientWidth})`);
  }
  // overlapping text: compare line boxes for inline text, so a wrapped link is not mistaken for an overlap
  const leaves = all.filter(own);
  const boxes = (el) => (getComputedStyle(el).display === "inline" ? [...el.getClientRects()] : [el.getBoundingClientRect()]);
  const lb = leaves.map((el) => [el, boxes(el)]);
  for (let i = 0; i < lb.length; i++) for (let j = i + 1; j < lb.length; j++) {
    const [a, A] = lb[i], [b, B] = lb[j];
    if (a.contains(b) || b.contains(a)) continue;
    if (A.some((ra) => B.some((rb) => Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left) > 2 && Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top) > 2))) f.push(`overlapping text: ${name(a)} and ${name(b)}`);
  }
  // an icon belongs on the first line of the text it labels
  for (const icon of document.querySelectorAll("svg.ic")) {
    if (!vis(icon) || !icon.parentElement) continue;
    const text = [...icon.parentElement.childNodes].find((n) => n !== icon && ((n.nodeType === 3 && n.textContent.trim()) || (n.nodeType === 1 && n.tagName !== "svg" && n.textContent.trim() && getComputedStyle(n).display.startsWith("inline"))));
    if (!text) continue;
    const range = document.createRange(); range.selectNodeContents(text);
    const first = range.getClientRects()[0];
    const ir = icon.getBoundingClientRect();
    if (first && (ir.top + ir.bottom) / 2 < first.top - 2) f.push(`an icon left alone above its text: ${name(icon.parentElement)}`);
  }
  for (const [el] of lb) {
    const size = parseFloat(getComputedStyle(el).fontSize);
    if (size < 11.95) f.push(`text under 12 px: ${name(el)} (${size} px)`);
  }
  const controls = all.filter((el) => el.matches("a[href], button, select, input:not([type=hidden]), textarea, summary, [role=button], [role=tab]"));
  for (const el of controls) {
    if (!(el.getAttribute("aria-label") || el.textContent.trim() || el.getAttribute("title") || el.labels?.length || el.getAttribute("aria-labelledby") || el.getAttribute("placeholder"))) f.push(`a control with no name: ${name(el)}`);
    const r = el.getBoundingClientRect();
    const inSentence = getComputedStyle(el).display === "inline" && el.parentElement && own(el.parentElement);
    if (!inSentence && (r.height < 23.5 || r.width < 23.5)) f.push(`a control smaller than 24 px: ${name(el)} (${Math.round(r.width)}x${Math.round(r.height)})`);
  }
  // contrast against the first solid background behind the text; a gradient or image behind it is measured by eye
  const rgb = (c) => { const n = (c.match(/-?[\d.]+/g) || ["0", "0", "0"]).map(Number); const k = c.startsWith("color(") ? 1 : 255; return { v: n.slice(0, 3).map((x) => x / k), a: n.length > 3 ? n[3] : 1 }; };
  const lum = (c) => { const [r, g, b] = rgb(c).v.map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4)); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
  const bgOf = (el) => { for (let e = el; e; e = e.parentElement) { const cs = getComputedStyle(e); if (cs.backgroundImage !== "none" && e !== document.body) return null; if (rgb(cs.backgroundColor).a > 0.85 && cs.backgroundColor !== "rgba(0, 0, 0, 0)") return cs.backgroundColor; } return getComputedStyle(document.body).backgroundColor; };
  for (const [el] of lb) {
    if (el.closest(":disabled, .disabled, [aria-disabled=true]")) continue;
    const cs = getComputedStyle(el), bg = bgOf(el);
    if (!bg) continue;
    const L1 = lum(cs.color), L2 = lum(bg), cr = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
    const big = parseFloat(cs.fontSize) >= 24 || (parseFloat(cs.fontSize) >= 18.66 && +cs.fontWeight >= 700);
    if (cr < (big ? 3 : 4.5)) f.push(`contrast ${cr.toFixed(2)}: ${name(el)}`);
  }
  return [...new Set(f)];
}

// ---- the walk ----------------------------------------------------------------------------------------------------

const SIZES = [[1440, 900], [1024, 768], [768, 1024], [390, 844]];
const PAGES = [
  ["overview", "#/"], ["analyze", "#/analyze"], ["analyze-link", "#/analyze", "link"], ["analyze-email", "#/analyze", "email"],
  ["events", "#/events"], ["event", "#/events", "event"], ["responses", "#/actions"], ["allow", "#/allow"], ["audit", "#/audit"],
  ["protection", "#/protection"], ["feedback", "#/feedback"], ["guide", "#/guide"],
];

let browser;
const errorsOf = new WeakMap();

async function openPage([w, h], scheme) {
  const page = await browser.newPage();
  await page.setViewport({ width: w, height: h, deviceScaleFactor: 1 });
  await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }]);
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  errorsOf.set(page, errors);
  return page;
}

async function signIn(page) {
  const { code } = await call("POST", "/v1/console/code");
  await page.goto("about:blank");
  await page.goto(`${base}/console/#code=${code}`, { waitUntil: "networkidle0" });
  await page.waitForSelector("main#content h2", { timeout: 15000 });
}

const go = async (page, hash) => { await page.evaluate((x) => { location.hash = x; }, hash); await sleep(700); };
const clickText = (page, text) => page.evaluate((t) => { const b = [...document.querySelectorAll("button, a")].find((x) => x.textContent.trim().startsWith(t)); if (!b) return false; b.click(); return true; }, text);

async function visit(page, [, hash, extra]) {
  await go(page, hash);
  if (extra === "link") { await clickText(page, "A trusted brand hidden"); await page.waitForSelector(".hero", { timeout: 20000 }).catch(() => undefined); await sleep(500); }
  if (extra === "email") { await clickText(page, "Email"); await sleep(300); await page.evaluate(() => document.querySelector("details.paste")?.setAttribute("open", "")); await sleep(200); }
  if (extra === "event") { await page.evaluate(() => document.querySelector("tbody a")?.click()); await page.waitForSelector(".hero", { timeout: 10000 }).catch(() => undefined); await sleep(500); }
}

async function layoutAudit() {
  for (const scheme of ["dark", "light"]) {
    for (const size of SIZES) {
      const tag = `${scheme}-${size[0]}`;
      const page = await openPage(size, scheme);
      await page.goto(`${base}/console/`, { waitUntil: "networkidle0" });
      for (const x of await page.evaluate(measure)) fault(`${tag} sign-in`, x);
      await page.screenshot({ path: join(out, `${tag}-00-sign-in.png`), fullPage: true });
      await signIn(page);
      for (const p of PAGES) {
        await visit(page, p);
        const heading = await page.evaluate(() => document.querySelector("main#content h2")?.textContent ?? "");
        if (!heading) fault(`${tag} ${p[0]}`, "the page has no heading (missing page?)");
        // measured first: that also scrolls back to the top, so the screenshot shows the page from its start and
        // never a pinned bar stuck halfway down a full-page picture
        for (const x of await page.evaluate(measure)) fault(`${tag} ${p[0]}`, x);
        await page.screenshot({ path: join(out, `${tag}-${p[0]}.png`), fullPage: true });
      }
      if (size[0] <= 860) {
        const opened = await page.evaluate(() => { const b = document.querySelector("[data-menu-button]"); b?.click(); return !!b; });
        await sleep(300);
        if (!opened) fault(tag, "no menu button on a narrow screen");
        else {
          await page.screenshot({ path: join(out, `${tag}-menu.png`), fullPage: false });
          for (const x of await page.evaluate(measure)) fault(`${tag} menu`, x);
        }
      }
      for (const e of errorsOf.get(page)) fault(tag, `console error: ${e}`);
      await page.close();
    }
  }
}

/** The new tabs say exactly what the core reports. */
async function tabsCheck() {
  const page = await openPage([1440, 900], "dark");
  await signIn(page);
  const intel = await call("GET", "/v1/intel/health");
  await go(page, "#/protection");
  const shown = await page.evaluate(() => ({
    providers: [...document.querySelectorAll("[data-provider]")].map((e) => ({ name: e.getAttribute("data-provider"), usable: e.getAttribute("data-usable"), text: e.textContent })),
    feeds: [...document.querySelectorAll("[data-feed]")].map((e) => ({ name: e.getAttribute("data-feed"), entries: e.getAttribute("data-entries"), text: e.textContent })),
    mailbox: !!document.querySelector("[data-mailbox]"), engine: !!document.querySelector("[data-engine]"),
  }));
  const names = (xs) => xs.map((x) => x.name ?? x.provider ?? x.feed).sort().join(",");
  if (names(shown.providers) !== names(intel.providers)) fault("protection", `providers shown ${names(shown.providers)} but the core reports ${names(intel.providers)}`);
  for (const p of intel.providers) {
    const row = shown.providers.find((s) => s.name === p.provider);
    if (row && row.usable !== (p.usable ? "yes" : "no")) fault("protection", `${p.provider} shown as usable=${row.usable}`);
    if (row && !row.text.includes(p.provider)) fault("protection", `${p.provider} row does not name it`);
  }
  if (shown.feeds.map((x) => x.name).sort().join(",") !== intel.feeds.map((x) => x.feed).sort().join(",")) fault("protection", "the feeds shown differ from the core's");
  for (const fd of intel.feeds) {
    const row = shown.feeds.find((s) => s.name === fd.feed);
    if (row && Number(row.entries) !== fd.entries) fault("protection", `${fd.feed} shows ${row.entries} entries, the core says ${fd.entries}`);
    if (row && !row.text.replace(/[^\d]/g, "").includes(String(fd.entries))) fault("protection", `${fd.feed} row does not show its ${fd.entries} entries`);
  }
  if (!shown.mailbox || !shown.engine) fault("protection", "the engine or the mailbox is missing");

  const rules = await call("GET", "/v1/feedback/rules");
  await go(page, "#/feedback");
  const fb = await page.evaluate(() => [...document.querySelectorAll("[data-rule]")].map((e) => ({ rule: e.getAttribute("data-rule"), fa: e.getAttribute("data-false-alarm"), ok: e.getAttribute("data-correct"), missed: e.getAttribute("data-missed"), text: e.textContent })));
  if (rules.length === 0) fault("feedback", "the seed produced no feedback to compare");
  if (fb.length !== rules.length) fault("feedback", `${fb.length} rules shown, the core reports ${rules.length}`);
  for (const r of rules) {
    const row = fb.find((x) => x.rule === r.rule_id);
    if (!row) { fault("feedback", `${r.rule_id} missing`); continue; }
    if (+row.fa !== r.false_alarm || +row.ok !== r.correct || +row.missed !== r.missed) fault("feedback", `${r.rule_id} counts differ from the core`);
    if (!row.text.includes(r.rule_id)) fault("feedback", `${r.rule_id} row does not name the rule`);
  }

  await go(page, "#/guide");
  const guide = await page.evaluate(() => ({ verdicts: [...document.querySelectorAll("[data-verdict]")].map((e) => e.getAttribute("data-verdict")), responses: [...document.querySelectorAll("[data-response]")].map((e) => e.getAttribute("data-response")), text: document.querySelector("main")?.textContent ?? "" }));
  for (const v of ["MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN", "ERROR"]) if (!guide.verdicts.includes(v) || !guide.text.includes(v)) fault("guide", `${v} is not explained`);
  for (const r of ["approve", "dismiss", "restore", "restore_allow", "retry"]) if (!guide.responses.includes(r)) fault("guide", `the response "${r}" is not explained`);
  for (const e of errorsOf.get(page)) fault("tabs", `console error: ${e}`);
  await page.close();
}

/** At phone width every page is reachable from the menu, which opens, closes on Escape and gives focus back. */
async function menuCheck() {
  const page = await openPage([390, 844], "dark");
  await signIn(page);
  const links = await page.evaluate(() => [...document.querySelectorAll("[data-menu] a[href^='#/']")].map((a) => a.getAttribute("href")));
  if (links.length < 9) fault("menu", `the menu lists ${links.length} pages, expected 9`);
  for (const href of links) {
    await page.click("[data-menu-button]");
    await sleep(250);
    const state = await page.evaluate((h) => {
      const b = document.querySelector("[data-menu-button]"), a = document.querySelector(`[data-menu] a[href="${h}"]`);
      const r = a?.getBoundingClientRect();
      return { expanded: b?.getAttribute("aria-expanded"), visible: !!r && r.width > 0 && r.top >= 0 && r.bottom <= innerHeight + 1 && getComputedStyle(a).visibility !== "hidden" };
    }, href);
    if (state.expanded !== "true") fault("menu", "the menu button does not say it is open");
    if (!state.visible) fault("menu", `${href} is not visible in the open menu`);
    await page.click(`[data-menu] a[href="${href}"]`);
    await sleep(500);
    const after = await page.evaluate(() => ({ hash: location.hash || "#/", expanded: document.querySelector("[data-menu-button]")?.getAttribute("aria-expanded"), heading: document.querySelector("main#content h2")?.textContent }));
    if (after.hash !== href) fault("menu", `choosing ${href} went to ${after.hash}`);
    if (after.expanded !== "false") fault("menu", `the menu stayed open after choosing ${href}`);
    if (!after.heading) fault("menu", `${href} shows no page`);
  }
  await page.click("[data-menu-button]");
  await sleep(200);
  await page.keyboard.press("Escape");
  await sleep(200);
  const esc = await page.evaluate(() => ({ expanded: document.querySelector("[data-menu-button]")?.getAttribute("aria-expanded"), focus: document.activeElement?.hasAttribute("data-menu-button") }));
  if (esc.expanded !== "false") fault("menu", "Escape does not close the menu");
  if (!esc.focus) fault("menu", "after Escape the focus is not back on the menu button");
  for (const e of errorsOf.get(page)) fault("menu", `console error: ${e}`);
  await page.close();
}

/** The theme switch beats the system setting, survives a reload, and System follows the system again. */
async function themeCheck() {
  const page = await openPage([1440, 900], "dark");
  await signIn(page);
  const bg = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  const light = (c) => { const [r, g, b] = c.match(/\d+/g).map(Number); return (r + g + b) / 3 > 128; };
  const choose = (v) => page.evaluate((x) => document.querySelector(`[data-theme-choice="${x}"]`)?.click(), v);
  if (light(await bg())) fault("theme", "System with a dark system setting is not dark");
  await choose("light"); await sleep(200);
  if (!light(await bg())) fault("theme", "choosing Light does not make it light");
  await page.reload({ waitUntil: "networkidle0" }); await sleep(300);
  if (!light(await bg())) fault("theme", "Light does not survive a reload");
  await choose("system"); await sleep(200);
  if (light(await bg())) fault("theme", "System does not follow the dark system setting again");
  await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: "light" }]); await sleep(200);
  if (!light(await bg())) fault("theme", "System does not follow a light system setting");
  await choose("dark"); await sleep(200);
  if (light(await bg())) fault("theme", "choosing Dark does not beat a light system setting");
  const pressed = await page.evaluate(() => document.querySelector('[data-theme-choice="dark"]')?.getAttribute("aria-pressed"));
  if (pressed !== "true") fault("theme", "the chosen theme is not marked as chosen");
  await choose("system");
  for (const e of errorsOf.get(page)) fault("theme", `console error: ${e}`);
  await page.close();
}

// ---- run ---------------------------------------------------------------------------------------------------------

let exitCode = 1;
try {
  await startCore(consoleDir());
  await seed();
  browser = await puppeteer.launch({ executablePath: EDGE, headless: true, userDataDir: join(work, "profile") });
  const step = async (label, fn) => { try { await fn(); } catch (e) { fault(label, `could not be checked: ${e.message.split("\n")[0]}`); } };
  if (!only) await step("layout", layoutAudit);
  if (!only || only === "tabs") await step("tabs", tabsCheck);
  if (!only || only === "menu") await step("menu", menuCheck);
  if (!only || only === "theme") await step("theme", themeCheck);
  for (const x of findings) console.log("FINDING " + x);
  console.log(`screenshots: ${out}`);
  if (expectFindings) {
    console.log(findings.length > 0 ? `NEGATIVE CONTROL: ${findings.length} findings on ${at}` : `no findings on ${at}: the audit could not tell a bad console from a good one`);
    exitCode = findings.length > 0 ? 0 : 1;
  } else if (findings.length > 0) {
    console.log(`${findings.length} finding(s)`);
  } else {
    console.log(only === "tabs" ? "TABS MATCH CORE" : only === "menu" ? "MENU REACHES EVERY PAGE" : only === "theme" ? "THEME SWITCH HOLDS" : "AUDIT CLEAN");
    exitCode = 0;
  }
} finally {
  await browser?.close().catch(() => undefined);
  stopCore();
  await sleep(500);
  if (!opt("--out")) for (const f of ["audit.db", "samples", "profile", "console", "old.tar"]) try { rmSync(join(work, f), { recursive: true, force: true }); } catch { /* a handle may linger */ }
}
process.exit(exitCode);
