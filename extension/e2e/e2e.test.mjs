// End to end, nothing faked: the built extension in a real Edge, the real native host, the real agent
// (which starts the real core), a synthetic phishing page on a *.localhost name, synthetic files.
// The user interface is never started. Run with: npm run test:e2e (needs `python tasks.py sandbox` once).
import { execFileSync, spawn } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { createServer as createTcp } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import puppeteer from "puppeteer-core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const REPO = resolve(import.meta.dirname, "..", "..");
const PY = join(REPO, ".venv", "Scripts", "python.exe");
const BIN = process.env.MIRAGE_AGENT_BIN ?? join(REPO, "agent", "Mirage.Agent", "bin", "Debug", "net10.0-windows10.0.19041.0");
const AGENT = join(BIN, "Mirage.Agent.exe");
const HOST = join(BIN, "Mirage.NativeHost.exe");
const DIST = join(REPO, "extension", "dist");
const EXT = "ahnnfchmgkcemcljobhnmmgfdgcajhfo";
const EDGE = ["C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"].find(existsSync);
const HOST_KEY = "HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.mirage.agent";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(check, what, ms = 60_000) {
  const start = Date.now();
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() - start > ms) throw new Error("timed out waiting for: " + what);
    await sleep(150);
  }
}
const freePort = () => new Promise((res) => { const s = createTcp(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
const py = (code, cwd = REPO) => execFileSync(PY, ["-c", code], { cwd, encoding: "utf8" });
const regQuery = () => { try { return /REG_SZ\s+(.*)/.exec(execFileSync("reg", ["query", HOST_KEY, "/ve"], { encoding: "utf8" }))?.[1]?.trim() ?? null; } catch { return null; } };

const world = {};
const requests = []; // what the fixture web server was asked for

beforeAll(async () => {
  if (!EDGE) throw new Error("Microsoft Edge is not installed");
  for (const f of [PY, AGENT, HOST, join(DIST, "manifest.json")]) if (!existsSync(f)) throw new Error("missing: " + f + " (build the agent and the extension first)");
  const tmp = mkdtempSync(join(tmpdir(), "mirage-e2e-"));
  Object.assign(world, { tmp, home: join(tmp, "home"), watched: join(tmp, "watched"), samples: join(tmp, "samples"), db: join(tmp, "mirage.db").replaceAll("\\", "/") });
  for (const d of [world.home, world.watched, world.samples]) mkdirSync(d, { recursive: true });
  world.corePort = await freePort();
  world.webPort = await freePort();

  py(`from sqlalchemy import create_engine\nfrom core.db import models as db\ndb.Base.metadata.create_all(create_engine('sqlite:///${world.db}'))`);
  py(
    `import sys\nsys.path[:0] = ['tests', 'core/sandbox/guest']\nimport filehelp as fh\n` +
      `open(r'${world.samples}\\bundle.zip','wb').write(fh.make_zip({'run.scr': b'x'}))\n` +
      `open(r'${world.samples}\\form.pdf','wb').write(fh.PDF_JS)\n`,
  );
  writeFileSync(join(world.samples, "invoice.pdf.exe"), Buffer.concat([Buffer.from([0x4d, 0x5a, 0x90, 0x00]), Buffer.alloc(60)]));
  writeFileSync(join(world.samples, "notes.txt"), "just some words, nothing else");

  writeFileSync(
    join(world.home, "agent.json"),
    JSON.stringify({
      CoreUrl: `http://127.0.0.1:${world.corePort}`,
      WatchFolders: [world.watched],
      StableMillis: 300,
      TickMillis: 50,
      CoreCommand: PY,
      CoreWorkingDir: REPO,
      CoreArgs: ["-m", "uvicorn", "core.api.app:create_app", "--factory", "--host", "127.0.0.1", "--port", String(world.corePort), "--no-access-log", "--no-server-header"],
    }),
  );

  // the browser looks this up by name; remember what was there and put it back afterwards
  world.oldHost = regQuery();
  const manifest = join(world.home, "com.mirage.agent.json");
  writeFileSync(manifest, JSON.stringify({ name: "com.mirage.agent", description: "e2e", path: HOST, type: "stdio", allowed_origins: [`chrome-extension://${EXT}/`] }));
  execFileSync("reg", ["add", HOST_KEY, "/ve", "/d", manifest, "/f"]);

  world.env = { ...process.env, MIRAGE_AGENT_HOME: world.home, MIRAGE_DATABASE_URL: `sqlite:///${world.db}` };
  delete world.env.MIRAGE_API_TOKEN;
  world.agent = spawn(AGENT, [], { env: world.env, windowsHide: true, stdio: "ignore" });
  await until(async () => { try { return (await fetch(`http://127.0.0.1:${world.corePort}/health`)).ok; } catch { return false; } }, "the agent to start the core");

  world.web = createServer((req, res) => { requests.push(req.url); res.setHeader("content-type", "text/html"); res.end("<!doctype html><title>fixture</title><h1>fixture page</h1>"); });
  await new Promise((r) => world.web.listen(world.webPort, "127.0.0.1", r));
});

afterAll(async () => {
  await world.browser?.close().catch(() => undefined);
  await world.headful?.close().catch(() => undefined);
  if (world.agent?.pid) try { execFileSync("taskkill", ["/PID", String(world.agent.pid), "/T", "/F"], { stdio: "ignore" }); } catch { /* already gone */ }
  world.web?.close();
  if (world.oldHost) execFileSync("reg", ["add", HOST_KEY, "/ve", "/d", world.oldHost, "/f"]);
  else try { execFileSync("reg", ["delete", HOST_KEY, "/f"], { stdio: "ignore" }); } catch { /* not there */ }
  await sleep(500);
  try { rmSync(world.tmp, { recursive: true, force: true }); } catch { /* a log may still be open */ }
});

const rows = () => JSON.parse(py(`import json, sqlite3\nc = sqlite3.connect(r'${world.db}')\nprint(json.dumps(c.execute("select a.kind, a.host, v.state, e.source from artifacts a join verdicts v on v.artifact_id = a.id join events e on e.id = a.event_id").fetchall()))`));
const audit = () => JSON.parse(py(`import json, sqlite3\nc = sqlite3.connect(r'${world.db}')\nprint(json.dumps(c.execute("select actor, action, detail from audit_logs").fetchall()))`));
const log = () => (existsSync(join(world.home, "agent.log")) ? readFileSync(join(world.home, "agent.log"), "utf8") : "");

describe("acceptance 1 and 3: with no user interface, files dropped in the folder are judged", () => {
  it("flags the test files, leaves the plain one, stores records by hash and host only, and tries a notification", async () => {
    for (const f of ["invoice.pdf.exe", "bundle.zip", "form.pdf", "notes.txt"]) copyFileSync(join(world.samples, f), join(world.watched, f));
    const files = await until(() => { const r = rows().filter((x) => x[0] === "FILE"); return r.length >= 4 ? r : false; }, "four stored file verdicts");
    const states = files.map((r) => r[2]).sort();
    expect(states.filter((s) => s === "SUSPICIOUS" || s === "MALICIOUS")).toHaveLength(3);
    expect(states.filter((s) => s === "UNKNOWN")).toHaveLength(1);
    expect(files.every((r) => r[3] === "AGENT")).toBe(true);
    const text = log();
    expect(text).not.toMatch(/invoice|bundle\.zip|form\.pdf|notes\.txt|\\samples|\\watched/);
    expect((text.match(/a notification was shown|could not be shown/g) ?? []).length).toBeGreaterThanOrEqual(3);
  });
});

const phish = (path = "/signin/login.php?email=jane%40example.test") => `http://paypal-secure-login.localhost:${world.webPort}${path}`;
const benign = () => `http://shop-fixture.localhost:${world.webPort}/`;
const onWarning = (page) => page.url().startsWith(`chrome-extension://${EXT}/warning.html`);

describe("acceptance 2: the browser half (headless Edge)", () => {
  beforeAll(async () => {
    world.browser = await puppeteer.launch({ executablePath: EDGE, headless: true, enableExtensions: [DIST], userDataDir: join(world.tmp, "profile"), env: world.env });
    world.worker = await world.browser.waitForTarget((t) => t.type() === "service_worker" && t.url().includes(EXT), { timeout: 30_000 });
  });

  it("an ordinary page is untouched", async () => {
    const page = await world.browser.newPage();
    await page.goto(benign());
    await sleep(1500);
    expect(page.url()).toBe(benign());
    expect(await page.$eval("h1", (e) => e.textContent)).toBe("fixture page");
    await page.close();
  });

  it("a phishing URL ends on the warning page, with the reasons, and its address is not echoed into markup", async () => {
    const page = await world.browser.newPage();
    await page.goto(phish()).catch(() => undefined);
    await until(() => onWarning(page), "the warning page");
    expect(await page.$eval("#title", (e) => e.textContent)).toMatch(/phishing|suspicious/);
    expect(await page.$$eval("#reasons li", (l) => l.length)).toBeGreaterThan(0);
    expect(await page.$eval("#url", (e) => e.textContent)).toContain("paypal-secure-login.localhost");
    world.warned = page;
  });

  it("continue anyway needs the agent to record it, then lets that exact URL through", async () => {
    const page = world.warned;
    await page.click("#continue");
    await until(() => page.url().startsWith(phish().split("?")[0]), "the real page");
    expect(await page.$eval("h1", (e) => e.textContent)).toBe("fixture page");
    const rec = await until(() => audit().find((r) => r[1] === "override.grant"), "an audit record");
    expect(rec[0]).toBe("user");
    expect(JSON.stringify(rec[2])).toContain("paypal-secure-login.localhost");
    expect(JSON.stringify(rec[2])).not.toContain("login.php");
    expect(JSON.stringify(rec[2])).not.toContain("jane");
    await page.close();
  });

  it("a browser-originated check is stored as such, by host and hash only", async () => {
    const stored = await until(() => { const r = rows().filter((x) => x[0] === "URL" && x[3] === "BROWSER"); return r.length ? r : false; }, "a BROWSER record");
    expect(stored[0][1]).toContain("localhost");
  });
});

describe("acceptance 2: instant blocking once site access is granted (headful Edge)", () => {
  it("a page judged bad is stopped before any request is sent", async (ctx) => {
    world.headful = await puppeteer.launch({ executablePath: EDGE, headless: false, enableExtensions: [DIST], userDataDir: join(world.tmp, "profile-headful"), env: world.env, args: ["--window-size=900,600"] });
    await world.headful.waitForTarget((t) => t.type() === "service_worker" && t.url().includes(EXT), { timeout: 30_000 });
    const options = await world.headful.newPage();
    await options.goto(`chrome-extension://${EXT}/options.html`);
    await options.click("#grant");
    // The browser may show its own permission prompt that automation cannot answer (it did not in this session on
    // 2026-11-05 evening, while it had earlier the same day). Then this check is skipped, loudly, never passed.
    const granted = await until(async () => (await options.$eval("#state", (e) => e.textContent)).includes("is on"), "site access granted", 20_000).then(() => true, () => false);
    if (!granted) {
      await world.headful.close();
      world.headful = null;
      ctx.skip("the browser did not accept the optional site-access request automatically in this session; the instant-block path was NOT checked");
    }

    const url = phish("/instant/login.php?email=jane%40example.test");
    const first = await world.headful.newPage();
    await first.goto(url).catch(() => undefined);
    await until(() => onWarning(first), "the first (asynchronous) warning");
    const seen = requests.filter((r) => r.startsWith("/instant/")).length;
    const second = await world.headful.newPage();
    await second.goto(url).catch(() => undefined);
    await until(() => onWarning(second), "the second (instant) warning");
    await sleep(500);
    expect(requests.filter((r) => r.startsWith("/instant/")).length).toBe(seen); // the server never saw the second visit
    await world.headful.close();
    world.headful = null;
  });
});

describe("acceptance 2: with the agent stopped", () => {
  it("pages load as normal and the toolbar badge says not protected", async () => {
    execFileSync("taskkill", ["/PID", String(world.agent.pid), "/T", "/F"], { stdio: "ignore" });
    await sleep(1500);
    const worker = await world.worker.worker();
    const page = await world.browser.newPage();
    await page.goto(phish("/stopped/login.php?x=1")).catch(() => undefined);
    await until(async () => (await worker.evaluate(() => chrome.action.getBadgeText({}))) === "!", "the not-protected badge", 30_000);
    await sleep(500);
    expect(onWarning(page)).toBe(false);
    expect(await page.$eval("h1", (e) => e.textContent)).toBe("fixture page");
    await page.close();
  });
});
