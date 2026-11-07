// End to end, nothing faked: the real agent starts the real core, a real Edge opens the built console, and the
// whole response flow runs with real files: flagged, waiting, quarantined, restored, allow-listed, failed, automatic.
// Run with: npm run test:e2e  (needs `python tasks.py sandbox` once and the agent built).
import { execFileSync, spawn } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer } from "node:net";
import puppeteer from "puppeteer-core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const REPO = resolve(import.meta.dirname, "..", "..");
const PY = join(REPO, ".venv", "Scripts", "python.exe");
const AGENT = join(process.env.LYNCEUS_AGENT_BIN ?? join(REPO, "agent", "Lynceus.Agent", "bin", "Debug", "net10.0-windows10.0.19041.0"), "Lynceus.Agent.exe");
const EDGE = ["C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"].find(existsSync);
const TOKEN = "e2e-" + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2) + "0123456789";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(check, what, ms = 90_000) {
  const start = Date.now();
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() - start > ms) throw new Error("timed out waiting for: " + what);
    await sleep(200);
  }
}
const freePort = () => new Promise((res) => { const s = createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
const py = (code) => execFileSync(PY, ["-c", code], { cwd: REPO, encoding: "utf8" });

const world = {};
const core = (path, init = {}) => fetch(`http://127.0.0.1:${world.corePort}${path}`, { ...init, headers: { Authorization: `Bearer ${TOKEN}`, ...(init.headers ?? {}) } });
const actions = async (state) => (await (await core(`/v1/actions?limit=200${state ? "&state=" + state : ""}`)).json());
const dbCount = (table) => Number(py(`import sqlite3\nprint(sqlite3.connect(r'${world.db}').execute("select count(*) from ${table}").fetchone()[0])`));

function startAgent(mode) {
  writeFileSync(
    join(world.home, "agent.json"),
    JSON.stringify({
      CoreUrl: `http://127.0.0.1:${world.corePort}`,
      WatchFolders: [world.watched],
      StableMillis: 300,
      TickMillis: 50,
      ResponseMode: mode,
      CoreCommand: PY,
      CoreWorkingDir: REPO,
      CoreArgs: ["-m", "uvicorn", "core.api.app:create_app", "--factory", "--host", "127.0.0.1", "--port", String(world.corePort), "--no-access-log", "--no-server-header"],
    }),
  );
  world.agent = spawn(AGENT, [], { env: world.env, windowsHide: true, stdio: "ignore" });
}
function stopAgent() {
  if (world.agent?.pid) try { execFileSync("taskkill", ["/PID", String(world.agent.pid), "/T", "/F"], { stdio: "ignore" }); } catch { /* gone */ }
}
const healthy = () => until(async () => { try { return (await fetch(`http://127.0.0.1:${world.corePort}/health`)).ok; } catch { return false; } }, "the core to answer");

beforeAll(async () => {
  for (const f of [EDGE, PY, AGENT, join(REPO, "console", "dist", "index.html")]) if (!f || !existsSync(f)) throw new Error("missing: " + f);
  const tmp = mkdtempSync(join(tmpdir(), "lynceus-console-e2e-"));
  Object.assign(world, { tmp, home: join(tmp, "home"), watched: join(tmp, "watched"), samples: join(tmp, "samples"), db: join(tmp, "lynceus.db").replaceAll("\\", "/") });
  for (const d of [world.home, world.watched, world.samples]) mkdirSync(d, { recursive: true });
  world.corePort = await freePort();
  py(`from sqlalchemy import create_engine\nfrom core.db import models as db\ndb.Base.metadata.create_all(create_engine('sqlite:///${world.db}'))`);
  py(
    `import sys\nsys.path[:0] = ['tests', 'core/sandbox/guest']\nimport filehelp as fh\n` +
      `base = fh.make_pdf('/OpenAction 4 0 R', ['<< /S /Launch /F (cmd.exe) >>', '<< /S /JavaScript /JS (x) >>', '<< /S /URI /URI (https://paypal-login.test/login.php?email=jane%40example.test) >>'])\n` +
      `for n in range(1, 5):\n    open(r'${world.samples}\\bad%d.pdf' % n, 'wb').write(base + b'\\n%%variant %d\\n' % n)\n`,
  );
  world.env = { ...process.env, LYNCEUS_AGENT_HOME: world.home, LYNCEUS_DATABASE_URL: `sqlite:///${world.db}`, LYNCEUS_API_TOKEN: TOKEN };
  startAgent("ask");
  await healthy();
  world.browser = await puppeteer.launch({ executablePath: EDGE, headless: true, userDataDir: join(tmp, "profile") });
  world.page = await world.browser.newPage();
  world.problems = [];
  world.page.on("console", (m) => { if (m.type() === "error") world.problems.push(m.text()); });
  world.page.on("pageerror", (e) => world.problems.push(String(e)));
});

afterAll(async () => {
  await world.browser?.close().catch(() => undefined);
  stopAgent();
  await sleep(500);
  try { rmSync(world.tmp, { recursive: true, force: true }); } catch { /* a log may still be open */ }
});

const bodyText = () => world.page.evaluate(() => document.body.innerText);
const waitText = (text, ms = 60_000) => world.page.waitForFunction((t) => document.body.innerText.includes(t), { timeout: ms }, text);
const click = (label) => world.page.evaluate((l) => {
  const b = [...document.querySelectorAll("button")].find((x) => x.textContent.trim() === l);
  if (!b) throw new Error("no button: " + l);
  b.click();
}, label);
const go = async (hash) => { await world.page.evaluate((h) => { window.location.hash = h; }, hash); await sleep(300); };
const drop = (name, as = name) => copyFileSync(join(world.samples, name), join(world.watched, as));
const same = (a, b) => readFileSync(a).equals(readFileSync(b));

describe("the console serves safely", () => {
  it("sends a strict policy and nothing outside its folder", async () => {
    const r = await fetch(`http://127.0.0.1:${world.corePort}/console/`);
    expect(r.status).toBe(200);
    expect(r.headers.get("content-security-policy")).toContain("default-src 'self'");
    expect(r.headers.get("x-content-type-options")).toBe("nosniff");
    expect((await fetch(`http://127.0.0.1:${world.corePort}/console/..%2f..%2f.env`)).status).not.toBe(200);
    expect((await fetch(`http://127.0.0.1:${world.corePort}/v1/events`)).status).toBe(401);
  });
});

describe("a malicious file waits for your decision, is quarantined on approval, and comes back on restore", () => {
  it("is flagged and proposed, and nothing moves by itself", async () => {
    drop("bad1.pdf");
    const [pending] = await until(async () => { const a = await actions("PENDING"); return a.length === 1 ? a : false; }, "a pending response");
    expect(pending.verdict_state).toBe("MALICIOUS");
    await sleep(2500);
    expect(existsSync(join(world.watched, "bad1.pdf"))).toBe(true);
    expect((await actions("PENDING")).length).toBe(1);
  });

  it("opens signed in, removes the token from the address and shows the waiting file", async () => {
    await world.page.goto(`http://127.0.0.1:${world.corePort}/console/#token=${TOKEN}`);
    await world.page.waitForSelector("nav");
    expect(world.page.url()).toBe(`http://127.0.0.1:${world.corePort}/console/`);
    await go("#/actions");
    await waitText("Waiting for your decision (1)");
    expect(await bodyText()).toContain("MALICIOUS");
  });

  it("says what will happen, then quarantines on the second click and audits it", async () => {
    await click("Quarantine");
    await waitText("Nothing is deleted");
    expect(existsSync(join(world.watched, "bad1.pdf"))).toBe(true);
    await click("Confirm: Quarantine");
    await waitText("In quarantine (1)");
    await until(() => !existsSync(join(world.watched, "bad1.pdf")), "the original to leave the folder");
    const quarantined = readdirSync(join(world.home, "quarantine"));
    expect(quarantined).toHaveLength(1);
    expect(readdirSync(join(world.home, "quarantine", quarantined[0])).sort()).toEqual(["payload.quar", "record.json"]);
    expect(readFileSync(join(world.home, "quarantine", quarantined[0], "payload.quar")).equals(readFileSync(join(world.samples, "bad1.pdf")))).toBe(true);
    await go("#/audit");
    await waitText("action.applied");
    const text = await bodyText();
    expect(text).toContain("action.approve");
    expect(text).not.toMatch(/bad1|\.pdf|samples|watched/);
  });

  it("shows the event with its evidence", async () => {
    await go("#/events");
    await waitText("MALICIOUS");
    await world.page.evaluate(() => document.querySelector("tbody a")?.click());
    await waitText("Why");
    const text = await bodyText();
    expect(text).toMatch(/email\.pdf_launch_action/);
    expect(text).toContain("Recommended: QUARANTINE");
  });

  it("restores the same bytes at the same place and does not flag its own restore as new", async () => {
    await go("#/actions");
    await waitText("In quarantine (1)");
    await click("Restore");
    await waitText("It will be dangerous again");
    await click("Confirm: Restore");
    await waitText("Done (1)");
    await until(() => existsSync(join(world.watched, "bad1.pdf")), "the file to come back");
    expect(same(join(world.watched, "bad1.pdf"), join(world.samples, "bad1.pdf"))).toBe(true);
    await sleep(4000);
    expect((await actions("PENDING")).length).toBe(0);
    expect(dbCount("actions")).toBe(1);
  });
});

describe("restore and don't flag again", () => {
  it("quarantines a second file, restores it with an allow entry, and then stays quiet about the same bytes", async () => {
    drop("bad2.pdf");
    await until(async () => (await actions("PENDING")).length === 1, "the second proposal");
    await go("#/actions");
    await waitText("Waiting for your decision (1)");
    await click("Quarantine");
    await click("Confirm: Quarantine");
    await waitText("In quarantine (1)");
    await click("Restore and don't flag again");
    await waitText("stop flagging this exact file");
    await click("Confirm: Restore and don't flag again");
    await until(() => existsSync(join(world.watched, "bad2.pdf")), "the file to come back");
    await go("#/allow");
    await waitText("Allow list");
    await until(async () => (await (await core("/v1/allowlist")).json()).length === 1, "an allow entry");

    const before = dbCount("actions");
    drop("bad2.pdf", "copy-of-bad2.pdf");
    await until(async () => (await (await core("/v1/events?limit=50")).json()).filter((e) => e.state === "MALICIOUS").length >= 3, "the copy to be judged");
    await sleep(3000);
    expect(dbCount("actions")).toBe(before);
    expect((await actions("PENDING")).length).toBe(0);
  });

  it("removes the entry again from the allow list, and the same bytes are proposed again", async () => {
    await go("#/allow");
    await waitText("Remove");
    await click("Remove");
    await click("Confirm: Remove");
    await waitText("Empty.");
    drop("bad2.pdf", "second-copy.pdf");
    await until(async () => (await actions("PENDING")).length === 1, "a proposal after the entry was removed");
  });
});

describe("failures are stated and nothing is lost", () => {
  it("a file changed after it was judged is left alone and the console says why", async () => {
    for (const a of await actions("PENDING")) await core(`/v1/actions/${a.id}/dismiss`, { method: "POST" });
    drop("bad3.pdf");
    await until(async () => (await actions("PENDING")).some((a) => a.verdict_state === "MALICIOUS" && a.sha256), "a proposal for bad3");
    const target = join(world.watched, "bad3.pdf");
    const pendingBefore = (await actions("PENDING")).length;
    appendFileSync(target, "\nchanged after the verdict\n");
    const mine = (await actions("PENDING")).find((a) => a.sha256 === createHashOf(join(world.samples, "bad3.pdf")));
    await core(`/v1/actions/${mine.id}/approve`, { method: "POST" });
    await until(async () => (await actions("FAILED")).length === 1, "the failure");
    expect(readFileSync(target, "utf8")).toContain("changed after the verdict");
    await go("#/actions");
    await waitText("Failed (1)");
    expect(await bodyText()).toContain("The file changed after it was checked, so Lynceus left it alone.");
    expect(pendingBefore).toBeGreaterThan(0);
  });
});

describe("signing in and out", () => {
  it("a wrong token returns to the sign-in screen and sign out forgets it", async () => {
    const page = await world.browser.newPage();
    await page.goto(`http://127.0.0.1:${world.corePort}/console/#token=${"x".repeat(32)}`);
    await page.waitForFunction(() => document.body.innerText.includes("Enter the API token"), { timeout: 30_000 });
    await page.close();
    await world.page.evaluate(() => [...document.querySelectorAll("button")].find((b) => b.textContent === "Sign out")?.click());
    await world.page.waitForFunction(() => document.body.innerText.includes("Enter the API token"));
    expect(await world.page.evaluate(() => window.sessionStorage.getItem("lynceus.token"))).toBeNull();
  });

  it("raised no policy violations or errors in the whole run", () => {
    expect(world.problems.filter((p) => !/401|Failed to load resource/.test(p))).toEqual([]);
  });
});

describe("automatic mode", () => {
  it("quarantines a malicious file on its own, and records that the policy decided", async () => {
    stopAgent();
    await sleep(1500);
    startAgent("auto");
    await healthy();
    drop("bad4.pdf");
    const done = await until(async () => (await actions("APPLIED")).find((a) => a.decided_by === "policy"), "an automatic quarantine");
    expect(done.verdict_state).toBe("MALICIOUS");
    await until(() => !existsSync(join(world.watched, "bad4.pdf")), "the original to be moved");
    const audit = await (await core("/v1/audit?limit=200")).json();
    expect(audit.some((r) => r.actor === "policy" && r.action === "action.approve")).toBe(true);
    expect(statSync(join(world.home, "quarantine")).isDirectory()).toBe(true);
  });
});

function createHashOf(file) {
  return py(`import hashlib\nprint(hashlib.sha256(open(r'${file}','rb').read()).hexdigest())`).trim();
}
