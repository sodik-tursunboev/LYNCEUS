import { describe, expect, it, vi } from "vitest";
import { ApiError, createApi } from "../src/api";
import { clearToken, getToken, openSession, setToken, signOut, takeCodeFromFragment, type Env } from "../src/auth";
import { compact, score, shortHash, when } from "../src/format";
import { consequence, group, GROUPS, LABEL, MAIL_LABEL, reasonText, verbsFor } from "../src/policy";
import type { ActionRow, ActionState } from "../src/types";

const TOKEN = "t".repeat(24);

function env(hash: string): Env & { store: Map<string, string>; replaced: string[] } {
  const store = new Map<string, string>();
  const replaced: string[] = [];
  return {
    store, replaced,
    storage: { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => void store.set(k, v), removeItem: (k) => void store.delete(k) },
    location: { hash, pathname: "/console/", search: "" },
    history: { replaceState: (_s, _t, url) => void replaced.push(String(url)) },
  };
}

describe("signing in", () => {
  it("takes a one-time code from the address once and removes it from the address", () => {
    const e = env(`#code=${TOKEN}`);
    expect(takeCodeFromFragment(e)).toBe(TOKEN);
    expect(getToken(e)).toBeNull(); // a code is not a session
    expect(e.replaced).toEqual(["/console/"]);
  });

  it.each(["#code=short", "#code=has space in it 1234567890", "#code=<script>alert(1)</script>xxxxxxxx", `#code=${"a".repeat(600)}`, `#token=${TOKEN}`])(
    "refuses %j but still removes it from the address", (hash) => {
      const e = env(hash);
      expect(takeCodeFromFragment(e)).toBeNull();
      expect(getToken(e)).toBeNull();
      expect(e.replaced).toHaveLength(1);
    },
  );

  it("leaves any other address alone", () => {
    const e = env("#/events");
    expect(takeCodeFromFragment(e)).toBeNull();
    expect(e.replaced).toEqual([]);
  });

  it("trades a code for a session and sends the code, not a token", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ token: "s".repeat(43), expires_in: 43200 }), { status: 200 }));
    expect(await openSession(fetchImpl as unknown as typeof fetch, { code: TOKEN })).toBe("s".repeat(43));
    const [path, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(path).toBe("/v1/console/session");
    expect(JSON.parse(String(init.body))).toEqual({ code: TOKEN });
    expect(new Headers(init.headers).get("Authorization")).toBeNull();
  });

  it("trades a typed API token for a session in the header only", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ token: "s".repeat(43) }), { status: 200 }));
    await openSession(fetchImpl as unknown as typeof fetch, { apiToken: ` ${TOKEN} ` });
    const [, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(new Headers(init.headers).get("Authorization")).toBe(`Bearer ${TOKEN}`);
    expect(String(init.body)).not.toContain(TOKEN);
  });

  it.each([
    [401, { detail: "no" }],
    [200, { token: "<script>alert(1)</script>xxxxxxxx" }],
    [200, { token: 12345 }],
    [200, {}],
  ])("gets no session from a %i answer %j", async (code, body) => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(body), { status: code }));
    expect(await openSession(fetchImpl as unknown as typeof fetch, { code: TOKEN })).toBeNull();
  });

  it("gets no session when the core is down", async () => {
    const fetchImpl = vi.fn(async () => { throw new TypeError("down"); });
    expect(await openSession(fetchImpl as unknown as typeof fetch, { code: TOKEN })).toBeNull();
  });

  it("signing out forgets the session here and ends it on the core", async () => {
    const e = env("");
    setToken(e, TOKEN);
    const fetchImpl = vi.fn(async () => new Response("{}", { status: 200 }));
    await signOut(fetchImpl as unknown as typeof fetch, e);
    expect(getToken(e)).toBeNull();
    const [path, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect([path, init.method]).toEqual(["/v1/console/session", "DELETE"]);
  });

  it("stores a typed token trimmed, and signing out forgets it", () => {
    const e = env("");
    setToken(e, `  ${TOKEN}  `);
    expect(getToken(e)).toBe(TOKEN);
    clearToken(e);
    expect(getToken(e)).toBeNull();
  });
});

describe("the API client", () => {
  const json = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status }));

  it("sends the token in a header, never in the address, and refuses redirects and cookies", async () => {
    const fetchMock = vi.fn(() => json([]));
    const api = createApi(fetchMock as unknown as typeof fetch, () => TOKEN, () => undefined);
    await api.events("MALICIOUS", 20);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/v1/events?state=MALICIOUS&limit=20");
    expect(url).not.toContain(TOKEN);
    expect(init).toMatchObject({ method: "GET", cache: "no-store", credentials: "omit", redirect: "error" });
    expect((init.headers as Record<string, string>).Authorization).toBe(`Bearer ${TOKEN}`);
  });

  it("encodes ids and bodies", async () => {
    const fetchMock = vi.fn(() => json({ state: "APPROVED", changed: true }));
    const api = createApi(fetchMock as unknown as typeof fetch, () => TOKEN, () => undefined);
    await api.approve("a/b?c");
    expect((fetchMock.mock.calls[0] as unknown as [string])[0]).toBe("/v1/actions/a%2Fb%3Fc/approve");
    await api.allowAdd("ab".repeat(32), 30);
    const [, init] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toEqual({ sha256: "ab".repeat(32), days: 30 });
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
  });

  it("signs you out on a 401 and makes no request without a token", async () => {
    const out = vi.fn();
    const rejected = createApi((() => json({}, 401)) as unknown as typeof fetch, () => TOKEN, out);
    await expect(rejected.audit()).rejects.toMatchObject({ status: 401 });
    expect(out).toHaveBeenCalledTimes(1);
    const fetchMock = vi.fn();
    const none = createApi(fetchMock as unknown as typeof fetch, () => null, out);
    await expect(none.health()).rejects.toBeInstanceOf(ApiError);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(out).toHaveBeenCalledTimes(2);
  });

  it.each([[404, /no longer exists/], [409, /not possible any more/], [422, /refused/], [503, /database/], [429, /Too many/], [500, /answered 500/]])(
    "turns a %i into words", async (status, words) => {
      const api = createApi((() => json({}, status)) as unknown as typeof fetch, () => TOKEN, () => undefined);
      await expect(api.actions()).rejects.toThrow(words);
    },
  );

  it("says the core is not reachable when the network fails", async () => {
    const api = createApi((() => Promise.reject(new TypeError("failed"))) as unknown as typeof fetch, () => TOKEN, () => undefined);
    await expect(api.health()).rejects.toMatchObject({ status: 0, message: "The core is not reachable." });
  });
});

describe("what each state offers", () => {
  const states: ActionState[] = ["PENDING", "APPROVED", "APPLIED", "DISMISSED", "FAILED", "RESTORE_REQUESTED", "RESTORED"];
  it("matches the rules the core enforces", () => {
    expect(Object.fromEntries(states.map((s) => [s, verbsFor(s)]))).toEqual({
      PENDING: ["approve", "dismiss"], APPROVED: ["dismiss"], APPLIED: ["restore", "restore_allow"], DISMISSED: ["approve"],
      FAILED: ["retry", "dismiss"], RESTORE_REQUESTED: [], RESTORED: [],
    });
  });

  it("never offers anything that deletes", () => {
    const all = Object.values(LABEL).join(" ").toLowerCase();
    expect(all).not.toMatch(/delete|remove file|purge|erase|wipe/);
  });

  it("says what will happen before it does", () => {
    expect(consequence("approve", 30)).toMatch(/Nothing is deleted/);
    expect(consequence("restore", 30)).toMatch(/dangerous again/);
    expect(consequence("restore_allow", 30)).toMatch(/30 days/);
    expect(consequence("restore_allow", null)).toMatch(/until you remove it/);
  });

  it("for email: the same rules, no allow-list shortcut, plain words, and nothing that deletes or sends", () => {
    const mail = Object.fromEntries(states.map((s) => [s, verbsFor(s, "MAIL_QUARANTINE")]));
    expect(mail.APPLIED).toEqual(["restore"]); // the allow list is by file hash: not for mail
    expect({ ...mail, APPLIED: 0 }).toEqual({ ...Object.fromEntries(states.map((s) => [s, verbsFor(s)])), APPLIED: 0 });
    expect(consequence("approve", 30, "MAIL_QUARANTINE", "gmail")).toMatch(/out of your inbox into the LYNCEUS-Quarantine label.*Nothing is deleted or sent/);
    expect(consequence("approve", 30, "MAIL_QUARANTINE", "outlook")).toMatch(/Lynceus Quarantine folder/);
    expect(consequence("restore", 30, "MAIL_QUARANTINE", "gmail")).toMatch(/back into your inbox/);
    const words = Object.values(MAIL_LABEL).join(" ").toLowerCase();
    expect(words).not.toMatch(/delete|purge|erase|wipe|send|trash/);
    expect(reasonText("message_gone")).toMatch(/no longer in the mailbox/);
    expect(reasonText("no_write_access")).toMatch(/Write access/);
  });

  it("groups every state into exactly one section", () => {
    const flat = GROUPS.flatMap((g) => g.states);
    expect([...flat].sort()).toEqual([...states].sort());
    const rows = states.map((state) => ({ state }) as ActionRow);
    expect(GROUPS.reduce((n, g) => n + group(rows, g.states).length, 0)).toBe(states.length);
  });

  it("explains reason codes, and shows an unknown one as plain text", () => {
    expect(reasonText("changed")).toMatch(/changed after it was checked/);
    expect(reasonText(null)).toBe("");
    expect(reasonText("<img src=x>")).toBe("Reason code: <img src=x>");
  });
});

describe("formatting", () => {
  it("shortens hashes, tolerates bad dates and unscored verdicts, and flattens audit details", () => {
    expect(shortHash("a".repeat(64))).toHaveLength(12);
    expect(shortHash(null)).toBe("");
    expect(when("not a date")).toBe("");
    expect(when(null)).toBe("");
    expect(score(null)).toBe("not scored");
    expect(score(80)).toBe("80");
    expect(compact({ sha12: "abc", from: "PENDING", reason: null, extra: { a: 1 } })).toBe('sha12: abc, from: PENDING, extra: {"a":1}');
    expect(compact(null)).toBe("");
  });
});