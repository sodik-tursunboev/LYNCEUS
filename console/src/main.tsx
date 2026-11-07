import { StrictMode, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { createApi, type Api } from "./api";
import { clearToken, getToken, setToken, takeTokenFromFragment } from "./auth";
import { Icon, type IconName } from "./Icon";
import { ActionsPage, AllowPage, AuditPage, EventPage, EventsPage, Overview } from "./pages";
import { Chip, useLoad } from "./ui";
import { AnalyzePage } from "./workbench";

const env = { storage: window.sessionStorage, location: window.location, history: window.history };
takeTokenFromFragment(env);

const PAGES: ReadonlyArray<readonly [hash: string, label: string, icon: IconName]> = [
  ["#/", "Overview", "Gauge"],
  ["#/analyze", "Analyze", "MagnifyingGlass"],
  ["#/events", "Events", "Pulse"],
  ["#/actions", "Responses", "ShieldCheck"],
  ["#/allow", "Allow list", "ListChecks"],
  ["#/audit", "Audit log", "Scroll"],
];

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
  const ok = value.trim().length >= 16;
  return (
    <main className="login">
      <div className="login-card">
        <Mark size={56} />
        <h1>Lynceus</h1>
        <p className="login-tag">A phishing solution kit that runs on your computer.</p>
        <p>Enter the API token. Start the console with <code>Lynceus.Agent.exe --open-console</code> to skip this.</p>
        <form onSubmit={(e) => { e.preventDefault(); if (ok) { setToken(env, value); onDone(); } }}>
          <label className="field">
            <span><Icon name="Key" weight="duotone" size={15} />API token</span>
            <input type="password" autoComplete="off" value={value} onChange={(e) => setValue(e.target.value)} aria-label="API token" placeholder="paste the token" />
          </label>
          <button className="btn primary big" type="submit" disabled={!ok}>Sign in</button>
        </form>
        <p className="login-fine"><Icon name="LockKey" weight="duotone" size={14} />The token stays in this tab and is forgotten when you close it.</p>
      </div>
    </main>
  );
}

function CoreStatus({ api }: { api: Api }) {
  const health = useLoad(() => api.health(), [api], 5000);
  const up = health.data?.status === "ok";
  return (
    <Chip tone={up ? "ok" : health.error ? "bad" : "info"} icon={up ? "Cpu" : "WarningOctagon"}>
      {up ? "Core running" : health.error ? "Core not reachable" : "Checking…"}
    </Chip>
  );
}

function App() {
  const [token, setTokenState] = useState(getToken(env));
  const [hash, setHash] = useState(window.location.hash || "#/");
  useEffect(() => {
    const on = () => { setHash(window.location.hash || "#/"); window.scrollTo(0, 0); };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  const api = useMemo(() => createApi(fetch.bind(window), () => getToken(env), () => { clearToken(env); setTokenState(null); }), []);
  if (!token) return <Login onDone={() => setTokenState(getToken(env))} />;
  const eventId = /^#\/events\/([0-9a-f-]{36})$/.exec(hash)?.[1];
  const current = eventId ? "#/events" : (PAGES.find(([h]) => h === hash)?.[0] ?? "#/");
  return (
    <div className="shell">
      <a className="skip" href="#content">Skip to the page</a>
      <aside className="side">
        <a className="brand" href="#/" aria-label="Lynceus, overview">
          <Mark />
          <span className="brand-text"><strong>LYNCEUS</strong><small>phishing solution kit</small></span>
        </a>
        <nav aria-label="Pages">
          {PAGES.map(([h, label, icon]) => (
            <a key={h} href={h} aria-current={h === current ? "page" : undefined}>
              <Icon name={icon} weight={h === current ? "duotone" : "regular"} size={20} />
              <span>{label}</span>
            </a>
          ))}
        </nav>
        <div className="side-foot">
          <CoreStatus api={api} />
          <button type="button" className="btn ghost" onClick={() => { clearToken(env); setTokenState(null); }}>
            <Icon name="SignOut" size={16} />Sign out
          </button>
        </div>
      </aside>
      <main id="content" tabIndex={-1}>
        {eventId ? <EventPage api={api} id={eventId} />
          : current === "#/analyze" ? <AnalyzePage api={api} />
          : current === "#/events" ? <EventsPage api={api} />
          : current === "#/actions" ? <ActionsPage api={api} />
          : current === "#/allow" ? <AllowPage api={api} />
          : current === "#/audit" ? <AuditPage api={api} />
          : <Overview api={api} />}
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
