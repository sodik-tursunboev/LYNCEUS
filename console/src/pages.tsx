import { useState } from "react";
import type { Api } from "./api";
import { compact, score, shortHash, when } from "./format";
import { consequence, group, GROUPS, LABEL, reasonText, verbsFor, type Verb } from "./policy";
import type { ActionRow } from "./types";
import { Badge, ConfirmButton, ErrorLine, Hash, useLoad } from "./ui";

export function Overview({ api }: { api: Api }) {
  const health = useLoad(() => api.health(), [api], 5000);
  const mailbox = useLoad(() => api.mailbox(), [api], 5000);
  const actions = useLoad(() => api.actions(undefined, 200), [api], 3000);
  const events = useLoad(() => api.events(undefined, 200), [api], 5000);
  const waiting = actions.data?.filter((a) => a.state === "PENDING").length ?? 0;
  const quarantined = actions.data?.filter((a) => a.state === "APPLIED").length ?? 0;
  const bad = events.data?.filter((e) => e.state === "MALICIOUS" || e.state === "SUSPICIOUS").length ?? 0;
  return (
    <>
      <h2>Overview</h2>
      <ErrorLine error={health.error ?? actions.error} />
      <div className="cards">
        <div className="card"><div className="muted">Core</div><div className="big">{health.data?.status === "ok" ? "running" : "…"}</div></div>
        <div className="card"><div className="muted">Waiting for your decision</div><div className="big">{waiting}</div><a href="#/actions">Open</a></div>
        <div className="card"><div className="muted">In quarantine</div><div className="big">{quarantined}</div></div>
        <div className="card"><div className="muted">Flagged recently</div><div className="big">{bad}</div><a href="#/events">Open</a></div>
        <div className="card"><div className="muted">Gmail</div><div className="big">{mailbox.data?.state ?? "…"}</div></div>
      </div>
      <p className="muted">This console only shows what MIRAGE found and carries out your decisions. Monitoring runs without it.</p>
    </>
  );
}

export function EventsPage({ api }: { api: Api }) {
  const [state, setState] = useState("");
  const events = useLoad(() => api.events(state || undefined, 100), [api, state], 5000);
  return (
    <>
      <h2>Events</h2>
      <div className="row">
        <label>Show <select value={state} onChange={(e) => setState(e.target.value)} aria-label="Filter by verdict">
          <option value="">everything</option>
          <option value="MALICIOUS">malicious</option>
          <option value="SUSPICIOUS">suspicious</option>
          <option value="UNKNOWN">unknown</option>
          <option value="ERROR">errors</option>
        </select></label>
      </div>
      <ErrorLine error={events.error} />
      <div className="panel">
        <table>
          <thead><tr><th>When</th><th>Kind</th><th>Where from</th><th>Verdict</th><th>Score</th><th>Signs</th><th>Response</th></tr></thead>
          <tbody>
            {events.data?.map((e) => (
              <tr key={e.id}>
                <td>{when(e.created_at)}</td>
                <td>{e.kind}</td>
                <td className="mono">{e.host ?? ""}</td>
                <td><a href={`#/events/${e.id}`}><Badge value={e.state} /></a></td>
                <td>{score(e.risk_score)}</td>
                <td className="mono">{e.rules.slice(0, 3).join(", ")}</td>
                <td>{e.action_state ? <a href="#/actions"><Badge value={e.action_state} /></a> : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {events.data && events.data.length === 0 ? <p className="muted">Nothing yet.</p> : null}
      </div>
    </>
  );
}

export function EventPage({ api, id }: { api: Api; id: string }) {
  const event = useLoad(() => api.event(id), [api, id]);
  const e = event.data;
  return (
    <>
      <p><a href="#/events">← Events</a></p>
      <ErrorLine error={event.error} />
      {e ? (
        <>
          <h2>{e.kind} from {e.host ?? "an unknown place"}</h2>
          <div className="panel">
            <p><Badge value={e.state} /> score {score(e.risk_score)} · {when(e.created_at)} · source {e.source}</p>
            <p>{e.explanation}</p>
            <p className="muted">Recommended: {e.recommended}. Applied: {e.applied}.</p>
            {e.action_state ? <p>Response: <Badge value={e.action_state} /> <a href="#/actions">decide</a></p> : null}
          </div>
          <h2>Why</h2>
          <div className="panel"><table>
            <thead><tr><th>Sign</th><th>Kind</th><th>Weight</th><th>What it means</th><th>ATT&amp;CK</th></tr></thead>
            <tbody>{e.signals.map((s) => (
              <tr key={s.rule_id}><td className="mono">{s.rule_id}</td><td>{s.category}</td><td>{s.weight}</td><td>{s.description}</td><td>{s.attack ?? ""}</td></tr>
            ))}</tbody>
          </table>{e.signals.length === 0 ? <p className="muted">No signs fired.</p> : null}</div>
          <h2>Evidence</h2>
          <div className="panel"><ul>{e.evidence.map((x, i) => (
            <li key={i}><strong>{x.kind}</strong>: {x.summary} {x.sha256 ? <Hash value={x.sha256} /> : null}</li>
          ))}</ul>{e.evidence.length === 0 ? <p className="muted">No evidence items.</p> : null}</div>
          <h2>Outside opinions</h2>
          <div className="panel"><table>
            <thead><tr><th>Provider</th><th>Answered</th><th>Opinion</th><th>When</th><th>Source</th></tr></thead>
            <tbody>{e.providers.map((p, i) => (
              <tr key={i}><td>{p.provider}</td><td>{p.status}</td><td>{p.state ?? "none"}</td><td>{when(p.queried_at)}</td><td>{p.provenance}</td></tr>
            ))}</tbody>
          </table>{e.providers.length === 0 ? <p className="muted">No outside provider was asked (this is the normal, offline setting).</p> : null}</div>
        </>
      ) : null}
    </>
  );
}

function ActionButtons({ api, action, reload }: { api: Api; action: ActionRow; reload: () => void }) {
  const [days, setDays] = useState<number | null>(30);
  const run = (verb: Verb) => async () => {
    if (verb === "approve" || verb === "retry") await api.approve(action.id);
    else if (verb === "dismiss") await api.dismiss(action.id);
    else if (verb === "restore") await api.restore(action.id);
    else {
      await api.allowAdd(action.sha256, days);
      await api.restore(action.id);
    }
    reload();
  };
  return (
    <div className="row">
      {verbsFor(action.state).map((verb) => (
        <ConfirmButton key={verb} label={LABEL[verb]} explain={consequence(verb, days)} onConfirm={run(verb)} danger={verb === "restore" || verb === "restore_allow"}>
          {verb === "restore_allow" ? (
            <label>Stop flagging it <select value={days === null ? "forever" : String(days)} onChange={(e) => setDays(e.target.value === "forever" ? null : Number(e.target.value))} aria-label="How long">
              <option value="30">for 30 days</option>
              <option value="365">for a year</option>
              <option value="forever">until I remove it</option>
            </select></label>
          ) : null}
        </ConfirmButton>
      ))}
    </div>
  );
}

export function ActionsPage({ api }: { api: Api }) {
  const actions = useLoad(() => api.actions(undefined, 200), [api], 3000);
  return (
    <>
      <h2>Responses</h2>
      <p className="muted">MIRAGE never deletes anything. A quarantined file is moved to a private folder and can be restored.</p>
      <ErrorLine error={actions.error} />
      {GROUPS.map((g) => {
        const rows = group(actions.data ?? [], g.states);
        return (
          <section key={g.title} aria-label={g.title}>
            <h2>{g.title} ({rows.length})</h2>
            <div className="panel">
              {rows.length === 0 ? <p className="muted">{g.empty}</p> : (
                <table>
                  <thead><tr><th>Verdict</th><th>File (hash)</th><th>State</th><th>Notes</th><th>Decide</th></tr></thead>
                  <tbody>{rows.map((a) => (
                    <tr key={a.id}>
                      <td><a href={`#/events/${a.verdict_id}`}><Badge value={a.verdict_state} /></a> {score(a.risk_score)}</td>
                      <td><Hash value={a.sha256} /></td>
                      <td><Badge value={a.state} /> <span className="muted">{when(a.created_at)}</span></td>
                      <td>{reasonText(a.reason)}{a.decided_by ? <span className="muted"> Decided by {a.decided_by}.</span> : null}</td>
                      <td><ActionButtons api={api} action={a} reload={actions.reload} /></td>
                    </tr>
                  ))}</tbody>
                </table>
              )}
            </div>
          </section>
        );
      })}
    </>
  );
}

export function AllowPage({ api }: { api: Api }) {
  const list = useLoad(() => api.allowList(), [api], 5000);
  return (
    <>
      <h2>Allow list</h2>
      <p className="muted">Files you told MIRAGE not to flag again (by exact content). They are still judged and recorded; they just no longer ask for a decision or raise a notification.</p>
      <ErrorLine error={list.error} />
      <div className="panel">
        {list.data && list.data.length === 0 ? <p className="muted">Empty.</p> : (
          <table>
            <thead><tr><th>File (hash)</th><th>Added</th><th>By</th><th>Until</th><th /></tr></thead>
            <tbody>{list.data?.map((a) => (
              <tr key={a.sha256}>
                <td><Hash value={a.sha256} /></td><td>{when(a.created_at)}</td><td>{a.created_by}</td>
                <td>{a.expires_at ? when(a.expires_at) : "until removed"}</td>
                <td><ConfirmButton label="Remove" explain={`MIRAGE will flag ${shortHash(a.sha256)} again if it sees it.`} onConfirm={async () => { await api.allowRemove(a.sha256); list.reload(); }} /></td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </div>
    </>
  );
}

export function AuditPage({ api }: { api: Api }) {
  const audit = useLoad(() => api.audit(200), [api], 5000);
  return (
    <>
      <h2>Audit log</h2>
      <p className="muted">Every decision and every action, newest first. Hashes are shortened; no file names or locations are ever recorded.</p>
      <ErrorLine error={audit.error} />
      <div className="panel"><table>
        <thead><tr><th>When</th><th>Who</th><th>What</th><th>About</th><th>Details</th></tr></thead>
        <tbody>{audit.data?.map((r) => (
          <tr key={r.id}><td>{when(r.at)}</td><td>{r.actor}</td><td className="mono">{r.action}</td><td>{r.target_type}{r.target_id ? ` ${r.target_id.slice(0, 8)}` : ""}</td><td className="mono">{compact(r.detail)}</td></tr>
        ))}</tbody>
      </table></div>
    </>
  );
}