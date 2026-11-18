import { useState } from "react";
import type { Api } from "./api";
import { relativeTime } from "./analysis";
import { collapseRepeats, compact, plural, ruleWords, score, shortHash, when } from "./format";
import { Icon } from "./Icon";
import { consequence, group, GROUPS, isMail, LABEL, MAIL_LABEL, reasonText, verbsFor, type Verb } from "./policy";
import { kindIcon, verdictMeta, type Tone } from "./theme";
import type { ActionRow, EventRow, FeedbackLabel } from "./types";
import { Badge, Chip, ConfirmButton, CopyButton, Distribution, Empty, ErrorLine, Gauge, Hash, PageTitle, Panel, Skeleton, Stat, useLoad } from "./ui";
import { SignalsPanel } from "./workbench";

const Ago = ({ iso }: { iso: string }) => <time dateTime={iso} title={when(iso)}>{relativeTime(iso, Date.now())}</time>;

/** What a detection with no host was, in words. */
const KIND_WORDS: Record<string, string> = { URL: "a link", EMAIL: "an email", FILE: "a file" };

const MAIL_TONE: Record<string, { tone: Tone; text: string }> = {
  connected: { tone: "ok", text: "connected" },
  reauth_needed: { tone: "warn", text: "sign-in needed" },
  error: { tone: "bad", text: "error" },
  disconnected: { tone: "info", text: "not connected" },
  off: { tone: "info", text: "not set up" },
};

export function Overview({ api }: { api: Api }) {
  const health = useLoad(() => api.health(), [api], 5000);
  const mailbox = useLoad(() => api.mailbox(), [api], 5000);
  const intel = useLoad(() => api.intelHealth(), [api], 30000);
  const actions = useLoad(() => api.actions(undefined, 200), [api], 3000);
  const events = useLoad(() => api.events(undefined, 200), [api], 5000);
  const waiting = actions.data?.filter((a) => a.state === "PENDING").length ?? 0;
  const quarantined = actions.data?.filter((a) => a.state === "APPLIED").length ?? 0;
  const flagged = events.data?.filter((e) => e.state === "MALICIOUS" || e.state === "SUSPICIOUS") ?? [];
  const feed = collapseRepeats(flagged).slice(0, 7);
  const mail = MAIL_TONE[mailbox.data?.state ?? ""] ?? { tone: "info" as Tone, text: mailbox.data?.state ?? "…" };
  const coreUp = health.data?.status === "ok";
  const usable = intel.data?.providers.filter((p) => p.usable).length ?? 0;
  const lookups = intel.data === null ? (intel.error ? "unknown" : "…") : intel.data.providers.length === 0 ? "off" : `${usable} of ${intel.data.providers.length} usable`;
  return (
    <>
      <PageTitle
        icon="Gauge" title="Overview" lead="What Lynceus found, and what is waiting for you."
        actions={<a className="btn primary" href="#/analyze"><Icon name="MagnifyingGlass" size={16} />Analyze something</a>}
      />
      <ErrorLine error={health.error ?? actions.error} />
      <div className="stats">
        <Stat icon="Heartbeat" label="Core" tone={coreUp ? "ok" : health.error ? "bad" : "info"} value={coreUp ? "running" : health.error ? "down" : "…"} note="the analysis engine" />
        <Stat icon="Hourglass" label="Waiting for you" tone={waiting > 0 ? "warn" : "accent"} value={waiting} href="#/actions" note={waiting > 0 ? "decide in Responses" : "nothing waiting"} />
        <Stat icon="Vault" label="In quarantine" value={quarantined} href="#/actions" note="all restorable" />
        <Stat icon="ShieldWarning" label="Flagged recently" tone={flagged.length > 0 ? "bad" : "ok"} value={flagged.length} href="#/events" note={`of the last ${events.data?.length ?? 0} events`} />
      </div>
      <div className="grid">
        <Panel title="Recent detections" icon="Pulse" actions={<a className="panel-link" href="#/events">All events <Icon name="ArrowRight" size={14} /></a>}>
          {events.data === null ? <Skeleton lines={4} /> : feed.length === 0 ? (
            <Empty icon="ShieldCheck" title="Nothing flagged">Links, files and mail are checked as they arrive. Detections will appear here.</Empty>
          ) : (
            <ul className="feed">
              {feed.map(({ item: e, count }) => (
                <li key={e.id}>
                  <span className="feed-icon"><Icon name={kindIcon(e.kind)} weight="duotone" size={20} /></span>
                  <a href={`#/events/${e.id}`} className="feed-main">
                    <strong className={e.host ? "mono" : undefined} title={e.host ?? undefined}>{e.host ?? KIND_WORDS[e.kind.toUpperCase()] ?? e.kind.toLowerCase()}</strong>
                    <span className="muted" title={e.rules.join(", ")}>{e.rules.slice(0, 3).map(ruleWords).join(" · ") || "no rule named"}</span>
                  </a>
                  <span className="feed-side">
                    <Badge value={e.state} size="sm" />
                    {count > 1 ? <span className="feed-count" title={`Judged the same way ${count} times`}>×{count}</span> : null}
                    <span className="muted feed-time"><Ago iso={e.created_at} /></span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <div className="stack">
          <Panel title="Verdicts" icon="ListChecks" actions={<span className="muted">last {events.data?.length ?? 0}</span>}>
            <Distribution items={events.data ?? []} />
          </Panel>
          <Panel title="Protection" icon="ShieldStar" actions={<a className="panel-link" href="#/protection">Details <Icon name="ArrowRight" size={14} /></a>}>
            <ul className="status-list">
              <li><Icon name="Cpu" weight="duotone" size={18} /><span>Analysis engine</span><Chip tone={coreUp ? "ok" : "bad"}>{coreUp ? "running" : "not reachable"}</Chip></li>
              <li><Icon name="EnvelopeSimple" weight="duotone" size={18} /><span>Mailbox</span><Chip tone={mail.tone}>{mail.text}</Chip></li>
              <li><Icon name="Broadcast" weight="duotone" size={18} /><span>Outside lookups</span><Chip tone={intel.data && usable < intel.data.providers.length ? "warn" : "info"}>{lookups}</Chip></li>
            </ul>
          </Panel>
          <NoisyRules api={api} />
        </div>
      </div>
      <p className="muted foot">This console only shows what Lynceus found and carries out your decisions. Monitoring runs without it.</p>
    </>
  );
}

const FILTERS: Array<{ value: string; label: string }> = [
  { value: "", label: "Everything" }, { value: "MALICIOUS", label: "Malicious" }, { value: "SUSPICIOUS", label: "Suspicious" },
  { value: "UNKNOWN", label: "Unknown" }, { value: "ERROR", label: "Errors" },
];
const KINDS: Array<{ value: string; label: string }> = [{ value: "", label: "All kinds" }, { value: "URL", label: "Links" }, { value: "EMAIL", label: "Email" }, { value: "FILE", label: "Files" }];

/** Events matching what was typed: host, rule id or its words, kind or verdict, case-insensitive. */
export function matchesSearch(e: Pick<EventRow, "host" | "rules" | "kind" | "state">, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [e.host ?? "", e.kind, e.state, ...e.rules, ...e.rules.map(ruleWords)].some((s) => s.toLowerCase().includes(q));
}

export function EventsPage({ api }: { api: Api }) {
  const [state, setState] = useState("");
  const [kind, setKind] = useState("");
  const [query, setQuery] = useState("");
  const events = useLoad(() => api.events(state || undefined, 100), [api, state], 5000);
  const shown = (events.data ?? []).filter((e) => (!kind || e.kind.toUpperCase() === kind) && matchesSearch(e, query));
  return (
    <>
      <PageTitle icon="Pulse" title="Events" lead="Every link, message and file Lynceus judged, newest first." />
      <div className="toolbar">
        <label className="search">
          <Icon name="MagnifyingGlass" size={16} />
          <input type="search" data-search value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search host, rule or kind" aria-label="Search events" />
        </label>
        <div className="segmented" role="group" aria-label="Filter by verdict">
          {FILTERS.map((f) => (
            <button key={f.value} type="button" className={state === f.value ? "seg on" : "seg"} aria-pressed={state === f.value} onClick={() => setState(f.value)}>{f.label}</button>
          ))}
        </div>
        <div className="segmented" role="group" aria-label="Filter by kind">
          {KINDS.map((k) => (
            <button key={k.value} type="button" className={kind === k.value ? "seg on" : "seg"} aria-pressed={kind === k.value} onClick={() => setKind(k.value)}>{k.label}</button>
          ))}
        </div>
      </div>
      <ErrorLine error={events.error} />
      <Panel>
        {events.data && events.data.length > 0 ? <p className="muted table-note" role="status">{shown.length === events.data.length ? `The last ${plural(events.data.length, "event")}.` : `${shown.length} of the last ${plural(events.data.length, "event")} match.`}</p> : null}
        <div className="table-wrap">
          <table className="data cards">
            <thead><tr><th>When</th><th>Kind</th><th>Where from</th><th>Verdict</th><th>Score</th><th>Signs</th><th>Response</th></tr></thead>
            <tbody>
              {shown.map((e) => (
                <tr key={e.id} className="event-row">
                  <td data-label="When" className="nowrap"><Ago iso={e.created_at} /></td>
                  <td data-label="Kind"><span className="cell-kind"><Icon name={kindIcon(e.kind)} weight="duotone" size={16} /><span>{e.kind.toLowerCase()}</span></span></td>
                  <td data-label="Where from" className="mono cell-wrap">{e.host ?? <span className="muted">{KIND_WORDS[e.kind.toUpperCase()] ?? ""}</span>}</td>
                  <td data-label="Verdict"><a href={`#/events/${e.id}`} className="badge-link" aria-label={`${e.state.toLowerCase()}: open this event`}><Badge value={e.state} size="sm" /></a></td>
                  <td data-label="Score" className={e.risk_score === null ? "mono nowrap no-score" : "mono nowrap"}>{score(e.risk_score)}</td>
                  <td data-label="Signs"><span className="chips">{e.rules.slice(0, 3).map((r) => <span key={r} title={r}><Chip>{ruleWords(r)}</Chip></span>)}</span></td>
                  <td data-label="Response">{e.action_state ? <a href="#/actions" className="badge-link"><Badge value={e.action_state} size="sm" /></a> : <span className="muted">none</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {events.data === null ? <Skeleton lines={5} /> : null}
        {events.data && events.data.length === 0 ? <Empty icon="Pulse" title="Nothing yet">New judgements will show up here as they happen.</Empty> : null}
        {events.data && events.data.length > 0 && shown.length === 0 ? <Empty icon="Funnel" title="Nothing matches">Try another word, or clear the filters.</Empty> : null}
      </Panel>
    </>
  );
}

export function EventPage({ api, id }: { api: Api; id: string }) {
  const event = useLoad(() => api.event(id), [api, id]);
  const e = event.data;
  const meta = e ? verdictMeta(e.state) : null;
  return (
    <>
      <p className="crumb"><a href="#/events"><Icon name="ArrowLeft" size={14} />Events</a></p>
      <ErrorLine error={event.error} />
      {e && meta ? (
        <>
          <section className={`hero tone-${meta.tone}`} aria-label="Verdict">
            <Gauge score={e.risk_score} state={e.state} />
            <div className="hero-main">
              <div className="eyebrow">
                <span className="eyebrow-item"><Icon name={kindIcon(e.kind)} size={14} />{e.kind.toLowerCase()}</span>
                <span className="eyebrow-item">{when(e.created_at)}</span>
                <span className="eyebrow-item">source {e.source.toLowerCase()}</span>
              </div>
              <h2 className="hero-title">{e.kind} from <span className="hero-host">{e.host ?? "an unknown place"}</span></h2>
              <p className="hero-meaning">{meta.meaning}</p>
              <p className="hero-why">{e.explanation}</p>
              <div className="chips">
                <Badge value={e.state} />
                <span className="muted">score {score(e.risk_score)}</span>
              </div>
              <p className="muted">Recommended: {e.recommended}. Applied: {e.applied}.</p>
              {e.action_state ? <p>Response: <Badge value={e.action_state} size="sm" /> <a href="#/actions">decide</a></p> : null}
            </div>
          </section>
          <FeedbackPanel api={api} id={e.id} state={e.state} given={e.feedback ?? null} />
          <div className="grid">
            <SignalsPanel signals={e.signals} />
            <div className="stack">
              <Panel title="Evidence" icon="Fingerprint">
                {e.evidence.length === 0 ? <p className="muted">No evidence items.</p> : (
                  <ul className="evidence">{e.evidence.map((x, i) => (
                    <li key={i}><Chip icon="Hash">{x.kind}</Chip><span className="evidence-text">{x.summary}</span>{x.sha256 ? <><Hash value={x.sha256} /><CopyButton text={x.sha256} label="Copy the full hash" /></> : null}</li>
                  ))}</ul>
                )}
              </Panel>
              <Panel title="Outside opinions" icon="Cloud">
                {e.providers.length === 0 ? <p className="muted">No outside provider was asked (this is the normal, offline setting).</p> : (
                  <ul className="providers">{e.providers.map((p, i) => (
                    <li key={i}><span className="provider-name">{p.provider}</span>{p.state ? <Badge value={p.state} size="sm" /> : <Chip tone="warn">{p.status.toLowerCase()}</Chip>}<span className="muted">{when(p.queried_at)} · {p.provenance}</span></li>
                  ))}</ul>
                )}
              </Panel>
            </div>
          </div>
        </>
      ) : event.error ? null : <Skeleton lines={6} />}
    </>
  );
}

const FEEDBACK_TEXT: Record<FeedbackLabel, string> = {
  correct: "You said this verdict was right.",
  false_alarm: "You said this was a false alarm.",
  missed: "You said this was phishing that Lynceus missed.",
};

/** "Was this right?" (H1 B3): your answer is stored and audited, and counted against the rules that fired. */
export function FeedbackPanel({ api, id, state, given }: { api: Api; id: string; state: string; given: FeedbackLabel | null }) {
  const [label, setLabel] = useState<FeedbackLabel | null>(given);
  const [error, setError] = useState<string | null>(null);
  const flagged = state === "MALICIOUS" || state === "SUSPICIOUS";
  const send = (next: FeedbackLabel) => async () => {
    try {
      await api.feedback(id, next);
      setLabel(next);
      setError(null);
    } catch {
      setError("Your answer could not be saved.");
    }
  };
  return (
    <Panel title="Was this right?" icon="Question">
      <p className="muted" role="status">{label ? FEEDBACK_TEXT[label] : "Your answer teaches Lynceus which of its rules are noisy on this computer."}</p>
      <div className="row">
        <button type="button" className="btn" aria-pressed={label === "correct"} onClick={send("correct")}><Icon name="CheckCircle" size={16} />Right</button>
        {flagged
          ? <button type="button" className="btn" aria-pressed={label === "false_alarm"} onClick={send("false_alarm")}><Icon name="ShieldSlash" size={16} />False alarm</button>
          : <button type="button" className="btn" aria-pressed={label === "missed"} onClick={send("missed")}><Icon name="Fish" size={16} />Missed phishing</button>}
      </div>
      <ErrorLine error={error} />
    </Panel>
  );
}

/** The rules whose verdicts you most often called false alarms. */
export function NoisyRules({ api }: { api: Api }) {
  const rules = useLoad(() => api.feedbackRules(), [api], 15000);
  const noisy = (rules.data ?? []).filter((r) => r.false_alarm > 0).slice(0, 8);
  return (
    <Panel title="Rules you called wrong" icon="ShieldSlash" actions={<a className="panel-link" href="#/feedback">All rules <Icon name="ArrowRight" size={14} /></a>}>
      <ErrorLine error={rules.error} />
      {noisy.length === 0 ? <p className="muted">No false alarms reported yet. Use "Was this right?" on an event, or "This warning is wrong" in the browser.</p> : (
        <ul className="noisy">{noisy.map((r) => (
          <li key={r.rule_id} title={r.rule_id}>
            <span className="noisy-name">{ruleWords(r.rule_id)}</span>
            <span className="noisy-counts"><span className="tone-bad">{plural(r.false_alarm, "false alarm")}</span><span className="muted">{r.correct} right</span></span>
          </li>
        ))}</ul>
      )}
    </Panel>
  );
}

function ActionButtons({ api, action, reload }: { api: Api; action: ActionRow; reload: () => void }) {
  const [days, setDays] = useState<number | null>(30);
  const mail = isMail(action.kind);
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
    <div className="row action-buttons">
      {verbsFor(action.state, action.kind).map((verb) => (
        <ConfirmButton
          key={verb} label={mail ? MAIL_LABEL[verb] : LABEL[verb]} explain={consequence(verb, days, action.kind, action.provider ?? null)} onConfirm={run(verb)}
          danger={verb === "restore" || verb === "restore_allow"} icon={verb === "approve" || verb === "retry" ? "Vault" : verb === "dismiss" ? "X" : "ArrowUUpLeft"}
        >
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
      <PageTitle
        icon="ShieldCheck" title="Responses"
        lead="Lynceus never deletes anything. A quarantined file is moved to a private folder, and a quarantined email to a label or folder in your mailbox; both can be restored."
      />
      <ErrorLine error={actions.error} />
      {GROUPS.map((g) => {
        const rows = group(actions.data ?? [], g.states);
        return (
          <section key={g.title} aria-label={g.title} className="group">
            <h3 className="group-title">{g.title} ({rows.length})</h3>
            {rows.length === 0 ? <p className="muted group-empty">{g.empty}</p> : (
              <ul className="actions">
                {rows.map((a) => (
                  <li key={a.id} className={`action tone-${verdictMeta(a.verdict_state).tone}`}>
                    <div className="action-id">
                      <Icon name={isMail(a.kind) ? "EnvelopeSimple" : "File"} weight="duotone" size={26} />
                      <div>
                        <a href={`#/events/${a.verdict_id}`} className="badge-link"><Badge value={a.verdict_state} size="sm" /></a>
                        <div className="muted small">score {score(a.risk_score)}</div>
                      </div>
                    </div>
                    <div className="action-what">
                      <div>{isMail(a.kind) ? <span>Email{a.provider ? ` (${a.provider})` : ""} </span> : null}<Hash value={a.sha256} /></div>
                      <div className="muted small"><Badge value={a.state} size="sm" /> <Ago iso={a.created_at} /></div>
                      {a.reason || a.decided_by ? (
                        <div className="small">{reasonText(a.reason)}{a.decided_by ? <span className="muted"> Decided by {a.decided_by}.</span> : null}</div>
                      ) : null}
                    </div>
                    <ActionButtons api={api} action={a} reload={actions.reload} />
                  </li>
                ))}
              </ul>
            )}
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
      <PageTitle
        icon="ListChecks" title="Allow list"
        lead="Files you told Lynceus not to flag again (by exact content). They are still judged and recorded; they just no longer ask for a decision or raise a notification."
      />
      <ErrorLine error={list.error} />
      <Panel>
        {list.data && list.data.length === 0 ? <Empty icon="ListChecks" title="Empty.">Use "Restore and don't flag again" on a quarantined file in Responses to add one.</Empty> : (
          <div className="table-wrap">
            <table className="data cards">
              <thead><tr><th>File (hash)</th><th>Added</th><th>By</th><th>Until</th><th><span className="sr-only">Remove</span></th></tr></thead>
              <tbody>{list.data?.map((a) => (
                <tr key={a.sha256}>
                  <td data-label="File (hash)"><span className="cell-hash"><Hash value={a.sha256} /><CopyButton text={a.sha256} label="Copy the full hash" /></span></td>
                  <td data-label="Added"><Ago iso={a.created_at} /></td><td data-label="By">{a.created_by}</td>
                  <td data-label="Until">{a.expires_at ? when(a.expires_at) : "until removed"}</td>
                  <td data-label="Remove"><ConfirmButton label="Remove" explain={`Lynceus will flag ${shortHash(a.sha256)} again if it sees it.`} onConfirm={async () => { await api.allowRemove(a.sha256); list.reload(); }} /></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
        {list.data === null ? <Skeleton lines={3} /> : null}
      </Panel>
    </>
  );
}

export function AuditPage({ api }: { api: Api }) {
  const audit = useLoad(() => api.audit(200), [api], 5000);
  return (
    <>
      <PageTitle
        icon="Scroll" title="Audit log"
        lead="Every decision and every action, newest first. Hashes are shortened; no file names or locations are ever recorded."
      />
      <ErrorLine error={audit.error} />
      <Panel>
        <div className="table-wrap">
          <table className="data cards">
            <thead><tr><th>When</th><th>Who</th><th>What</th><th>About</th><th>Details</th></tr></thead>
            <tbody>{audit.data?.map((r) => (
              <tr key={r.id}>
                <td data-label="When" className="nowrap"><Ago iso={r.at} /></td>
                <td data-label="Who"><Chip tone={r.actor === "user" ? "accent" : "info"}>{r.actor}</Chip></td>
                <td data-label="What" className="mono cell-wrap">{r.action}</td>
                <td data-label="About" className="cell-wrap">{r.target_type}{r.target_id ? <> <span className="mono">{r.target_id.slice(0, 8)}</span></> : ""}</td>
                <td data-label="Details" className="mono detail">{compact(r.detail) || <span className="muted">none</span>}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
        {audit.data === null ? <Skeleton lines={5} /> : null}
        {audit.data && audit.data.length === 0 ? <Empty icon="Scroll" title="Nothing recorded yet">Decisions and actions are written here as they happen.</Empty> : null}
      </Panel>
    </>
  );
}
