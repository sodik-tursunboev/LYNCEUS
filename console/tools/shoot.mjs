// Takes screenshots of the console for design review, with headless Edge in a throwaway profile.
//
//   node tools/shoot.mjs <base url> <token> <out dir> [width] [height]
//
// Needs a core serving the console (see docs/milestones/UI1.md). It only reads: it clicks a made-up example link,
// then walks every page. Used by the maintainer; not part of the test suite.
import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import puppeteer from "puppeteer-core";

const [base, token, out, w = "1440", h = "900"] = process.argv.slice(2);
if (!base || !token || !out) throw new Error("usage: node tools/shoot.mjs <base url> <token> <out dir> [width] [height]");
const EDGE = ["C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"].find(existsSync);
if (!EDGE) throw new Error("Microsoft Edge was not found");
mkdirSync(out, { recursive: true });
const profile = mkdtempSync(join(tmpdir(), "mirage-shoot-"));
const browser = await puppeteer.launch({ executablePath: EDGE, headless: true, userDataDir: profile, defaultViewport: { width: Number(w), height: Number(h), deviceScaleFactor: 1 } });
const page = await browser.newPage();
if (process.env.SCHEME === "light") await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: "light" }]);
const errors = [];
page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
page.on("pageerror", (e) => errors.push(String(e)));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const snap = async (name, full = true) => { await sleep(700); await page.screenshot({ path: join(out, `${name}.png`), fullPage: full }); console.log("saved", name); };
const click = (text) => page.evaluate((t) => { const b = [...document.querySelectorAll("button, a")].find((x) => x.textContent.trim().includes(t)); if (!b) throw new Error("no such control: " + t); b.click(); }, text);

try {
  await page.goto(`${base}/console/#token=${token}`, { waitUntil: "networkidle0" });
  await page.goto(`${base}/console/#/`, { waitUntil: "networkidle0" });
  await snap("01-overview");
  await page.evaluate(() => { location.hash = "#/analyze"; }); await sleep(500);
  await snap("02-analyze-empty");
  await click("A trusted brand hidden in the subdomain"); await sleep(1500);
  await snap("03-analyze-url-malicious");
  await click("A trusted name before the @"); await sleep(1500);
  await snap("04-analyze-url-userinfo");
  await page.evaluate(() => { location.hash = "#/events"; }); await sleep(800);
  await snap("05-events");
  await page.evaluate(() => document.querySelector("tbody a")?.click()); await sleep(900);
  await snap("06-event-detail");
  await page.evaluate(() => { location.hash = "#/actions"; }); await sleep(800);
  await snap("07-responses");
  await page.evaluate(() => { location.hash = "#/allow"; }); await sleep(600);
  await snap("08-allow");
  await page.evaluate(() => { location.hash = "#/audit"; }); await sleep(600);
  await snap("09-audit");
  await page.evaluate(() => { location.hash = "#/analyze"; }); await sleep(400);
  await click("Email"); await sleep(300);
  await snap("10-analyze-email-intake");
  if (process.env.EML) {
    const input = await page.$('input[type="file"]');
    await input.uploadFile(process.env.EML); await sleep(2500);
    await snap("11-analyze-email-result");
  }
  if (process.env.FILE) {
    await page.evaluate(() => { location.hash = "#/analyze"; }); await sleep(300);
    await click("File"); await sleep(300);
    const input = await page.$('input[type="file"]');
    await input.uploadFile(process.env.FILE); await sleep(3000);
    await snap("12-analyze-file-result");
  }
  console.log(errors.length ? "console errors:\n" + errors.join("\n") : "no console errors");
} finally {
  await browser.close();
  try { rmSync(profile, { recursive: true, force: true }); } catch { /* a handle may linger */ }
}
