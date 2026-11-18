import { StrictMode, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { createApi, type Api } from "./api";
import { clearToken, getToken, openSession, setToken, signOut, takeCodeFromFragment } from "./auth";
import { Icon, type IconName } from "./Icon";
import { isTyping, readKey } from "./keys";
import { ActionsPage, AllowPage, AuditPage, EventPage, EventsPage, Overview } from "./pages";
import { applyTheme, browserStore, readTheme, THEME_CHOICES, writeTheme, type ThemeChoice } from "./prefs";
import { FeedbackPage, GuidePage, ProtectionPage } from "./tabs";
import { Chip, useLoad } from "./ui";
import { AnalyzePage } from "./workbench";

const env = { storage: window.sessionStorage, location: window.location, history: window.history };
const pendingCode = takeCodeFromFragment(env);
const signingIn: Promise<void> = pendingCode
  ? openSession(fetch.bind(window), { code: pendingCode }).then((t) => { if (t) setToken(env, t); })
  : Promise.resolve();

type Page = readonly [hash: string, label: string, icon: IconName];
/** The pages, in the groups the sidebar shows them in (UI2). */
const GROUPS: ReadonlyArray<{ title: string; pages: ReadonlyArray<Page> }> = [
  { title: "Monitor", pages: [["#/", "Overview", "Gauge"], ["#/events", "Events", "Pulse"], ["#/actions", "Responses", "ShieldCheck"]] },
  { title: "Investigate", pages: [["#/analyze", "Analyze", "MagnifyingGlass"]] },
  { title: "Manage", pages: [["#/allow", "Allow list", "ListChecks"], ["#/feedback", "Feedback", "ChatCircleText"], ["#/audit", "Audit log", "Scroll"]] },
  { title: "System", pages: [["#/protection", "Protection", "ShieldStar"], ["#/guide", "Guide", "BookOpenText"]] },
];
const PAGES = GROUPS.flatMap((g) => g.pages);

/** The Lynceus mark: an eye in a shield (Lynceus, the Argonaut who saw through walls). */
export function Mark({ size = 34 }: { size?: number }) {
  return (
    <svg viewBox="0 0 64 64" width={size} height={size} aria-hidden="true" focusable="false" className="mark">
      <defs>
        <linearGradient id="mk" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#65f7ff" /><stop offset="1" stopColor="#00a9b3" /></linearGradient>
      </defs>
      <path d="M32 4 56 12v18c0 14-10 24-24 30C18 54 8 44 8 30V12Z" fill="none" stroke="url(#mk)" strokeWidth="3.2" strokeLinejoin="round" />
      <path d="M15 30q17-16 34 0q-17 16-34 0Z" fill="none" stroke="url(#mk)" strokeWidth="3" strokeLinejoin="round" />
      <circle cx="32" cy="30" r="5.2" fill="url(#mk)" />
    </svg>
  );
}

function Login({ onDone }: { onDone: () => void }) {
  const [value, setValue] = useState("");
  const [refused, setRefused] = useState(false);
  const ok = value.trim().length >= 16;
  const submit = async () => {
    const session = await openSession(fetch.bind(window), { apiToken: value });
    setValue(""); // the API token is never kept, only the session it opened
    if (!session) { setRefused(true); return; }
    setToken(env, session);
    onDone();
  };
  return (
    <main className="login">
      <div className="login-card">
        <Mark size={56} />
        <h1>Lynceus</h1>
        <p className="login-tag">A phishing solution kit that runs on your computer.</p>
        <p>Enter the API token. Start the console with <code>Lynceus.Agent.exe --open-console</code> to skip this.</p>
        {refused && <p className="login-error" role="alert">That token was not accepted.</p>}
        <form onSubmit={(e) => { e.preventDefault(); if (ok) void submit(); }}>
          <label className="field">
            <span><Icon name="Key" weight="duotone" size={15} />API token</span>
            <input type="password" autoComplete="off" value={value} onChange={(e) => setValue(e.target.value)} aria-label="API token" placeholder="paste the token" />
          </label>
          <button className="btn primary big" type="submit" disabled={!ok}>Sign in</button>
        </form>
        <p className="login-fine"><Icon name="LockKey" weight="duotone" size={14} /><span>The token opens a session for this tab and is not kept. The session ends when you sign out, close the tab or restart Lynceus.</span></p>
      </div>
    </main>
  );
}

function CoreStatus({ api }: { api: Api }) {
  const health = useLoad(() => api.health(), [api], 5000);
  const up = health.data?.status === "ok";
  return (
    <Chip tone={up ? "ok" : health.error ? "bad" : "info"} icon={up ? "Heartbeat" : "WarningOctagon"}>
      {up ? "Core running" : health.error ? "Core not reachable" : "Checking…"}
    </Chip>
  );
}

const THEME_ICON: Record<ThemeChoice, IconName> = { system: "CircleHalf", dark: "Moon", light: "Sun" };

function ThemeSwitch({ choice, onChoose }: { choice: ThemeChoice; onChoose: (c: ThemeChoice) => void }) {
  return (
    <div className="theme-switch" role="group" aria-label="Theme">
      {THEME_CHOICES.map((t) => (
        <button key={t.value} type="button" data-theme-choice={t.value} aria-pressed={choice === t.value} title={`Theme: ${t.label}`} onClick={() => onChoose(t.value)}>
          <Icon name={THEME_ICON[t.value]} weight={choice === t.value ? "fill" : "regular"} size={15} /><span>{t.label}</span>
        </button>
      ))}
    </div>
  );
}

function App() {
  const [token, setTokenState] = useState(getToken(env));
  const [ready, setReady] = useState(!pendingCode);
  const [hash, setHash] = useState(window.location.hash || "#/");
  const [menuOpen, setMenuOpen] = useState(false);
  const [theme, setTheme] = useState<ThemeChoice>(() => readTheme(browserStore()));
  const menuButton = useRef<HTMLButtonElement>(null);
  const waitingG = useRef<{ on: boolean; timer?: ReturnType<typeof setTimeout> }>({ on: false });

  useEffect(() => { void signingIn.then(() => { setTokenState(getToken(env)); setReady(true); }); }, []);
  useEffect(() => {
    const on = () => { setHash(window.location.hash || "#/"); setMenuOpen(false); window.scrollTo(0, 0); };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  useEffect(() => { applyTheme(document.documentElement, theme); writeTheme(browserStore(), theme); }, [theme]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && menuOpen) { setMenuOpen(false); menuButton.current?.focus(); return; }
      const step = readKey(e, waitingG.current.on, isTyping(e.target as HTMLElement | null));
      clearTimeout(waitingG.current.timer);
      waitingG.current = { on: step.waiting, timer: step.waiting ? setTimeout(() => { waitingG.current = { on: false }; }, 1500) : undefined };
      if (!step.result) return;
      e.preventDefault();
      if ("go" in step.result) window.location.hash = step.result.go;
      else document.querySelector<HTMLElement>("[data-search]")?.focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [menuOpen]);

  const api = useMemo(() => createApi(fetch.bind(window), () => getToken(env), () => { clearToken(env); setTokenState(null); }), []);
  if (!ready) return <main className="login" aria-busy="true"><div className="login-card"><Mark size={56} /><p>Signing in…</p></div></main>;
  if (!token) return <Login onDone={() => setTokenState(getToken(env))} />;
  const eventId = /^#\/events\/([0-9a-f-]{36})$/.exec(hash)?.[1];
  const current = eventId ? "#/events" : (PAGES.find(([h]) => h === hash)?.[0] ?? "#/");
  return (
    <div className="shell">
      <a className="skip" href="#content">Skip to the page</a>
      <aside className={menuOpen ? "side open" : "side"}>
        <div className="side-top">
          <a className="brand" href="#/" aria-label="Lynceus, overview">
            <Mark />
            <span className="brand-text"><strong>LYNCEUS</strong><small>phishing solution kit</small></span>
          </a>
          <button
            ref={menuButton} type="button" className="menu-btn" data-menu-button aria-expanded={menuOpen} aria-controls="site-menu"
            onClick={() => setMenuOpen((o) => !o)}
          >
            <Icon name={menuOpen ? "X" : "List"} size={20} /><span>{menuOpen ? "Close" : "Menu"}</span>
          </button>
        </div>
        <div className="side-menu" id="site-menu" data-menu>
          <nav aria-label="Pages">
            {GROUPS.map((g) => (
              <div key={g.title} className="nav-group">
                <p className="nav-group-title" aria-hidden="true">{g.title}</p>
                {g.pages.map(([h, label, icon]) => (
                  <a key={h} href={h} aria-current={h === current ? "page" : undefined} onClick={() => setMenuOpen(false)}>
                    <Icon name={icon} weight={h === current ? "duotone" : "regular"} size={20} />
                    <span>{label}</span>
                    {h === "#/actions" ? <PendingCount api={api} /> : null}
                  </a>
                ))}
              </div>
            ))}
          </nav>
          <div className="side-foot">
            <CoreStatus api={api} />
            <ThemeSwitch choice={theme} onChoose={setTheme} />
            <button type="button" className="btn ghost" onClick={() => { void signOut(fetch.bind(window), env); setTokenState(null); }}><Icon name="SignOut" size={16} />Sign out</button>
            <p className="side-keys"><Icon name="Keyboard" size={14} /><span><kbd>?</kbd> guide and shortcuts</span></p>
          </div>
        </div>
      </aside>
      <main id="content" tabIndex={-1}>
        {eventId ? <EventPage api={api} id={eventId} />
          : current === "#/analyze" ? <AnalyzePage api={api} />
          : current === "#/events" ? <EventsPage api={api} />
          : current === "#/actions" ? <ActionsPage api={api} />
          : current === "#/allow" ? <AllowPage api={api} />
          : current === "#/audit" ? <AuditPage api={api} />
          : current === "#/feedback" ? <FeedbackPage api={api} />
          : current === "#/protection" ? <ProtectionPage api={api} />
          : current === "#/guide" ? <GuidePage />
          : <Overview api={api} />}
      </main>
    </div>
  );
}

/** How many responses wait for a decision, next to "Responses" (nothing when none). */
function PendingCount({ api }: { api: Api }) {
  const pending = useLoad(() => api.actions("PENDING", 200), [api], 10000);
  const n = pending.data?.length ?? 0;
  return n > 0 ? <span className="nav-count" title={`${n} waiting for your decision`}>{n}<span className="sr-only"> waiting</span></span> : null;
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
