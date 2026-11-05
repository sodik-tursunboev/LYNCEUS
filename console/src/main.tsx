import { StrictMode, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { createApi } from "./api";
import { clearToken, getToken, setToken, takeTokenFromFragment } from "./auth";
import { ActionsPage, AllowPage, AuditPage, EventPage, EventsPage, Overview } from "./pages";

const env = { storage: window.sessionStorage, location: window.location, history: window.history };
takeTokenFromFragment(env);

const PAGES = [
  ["#/", "Overview"], ["#/events", "Events"], ["#/actions", "Responses"], ["#/allow", "Allow list"], ["#/audit", "Audit log"],
] as const;

function Login({ onDone }: { onDone: () => void }) {
  const [value, setValue] = useState("");
  return (
    <main className="login">
      <h1>MIRAGE console</h1>
      <p>Enter the API token. Start the console with <code>Mirage.Agent.exe --open-console</code> to skip this.</p>
      <form onSubmit={(e) => { e.preventDefault(); if (value.trim().length >= 16) { setToken(env, value); onDone(); } }}>
        <input type="password" autoComplete="off" value={value} onChange={(e) => setValue(e.target.value)} aria-label="API token" />
        <button className="primary" type="submit" disabled={value.trim().length < 16}>Sign in</button>
      </form>
    </main>
  );
}

function App() {
  const [token, setTokenState] = useState(getToken(env));
  const [hash, setHash] = useState(window.location.hash || "#/");
  useEffect(() => {
    const on = () => setHash(window.location.hash || "#/");
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  const api = useMemo(() => createApi(fetch.bind(window), () => getToken(env), () => { clearToken(env); setTokenState(null); }), []);
  if (!token) return <Login onDone={() => setTokenState(getToken(env))} />;
  const eventId = /^#\/events\/([0-9a-f-]{36})$/.exec(hash)?.[1];
  const current = eventId ? "#/events" : (PAGES.find(([h]) => h === hash)?.[0] ?? "#/");
  return (
    <>
      <header>
        <h1>MIRAGE</h1>
        <nav aria-label="Pages">{PAGES.map(([h, label]) => <a key={h} href={h} aria-current={h === current ? "page" : undefined}>{label}</a>)}</nav>
        <button onClick={() => { clearToken(env); setTokenState(null); }}>Sign out</button>
      </header>
      <main>
        {eventId ? <EventPage api={api} id={eventId} />
          : current === "#/events" ? <EventsPage api={api} />
          : current === "#/actions" ? <ActionsPage api={api} />
          : current === "#/allow" ? <AllowPage api={api} />
          : current === "#/audit" ? <AuditPage api={api} />
          : <Overview api={api} />}
      </main>
    </>
  );
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);