// The tabs UI2 adds: Protection (the state of every guard), Feedback (every rule you judged) and Guide (what the
// verdicts and responses mean, what stays on this computer, the shortcuts). They read only what the core already
// reports; nothing here changes anything.
import { useState, type ReactNode } from "react";
import type { Api } from "./api";
import { relativeTime } from "./analysis";
import { plural, ruleWords, when } from "./format";
import { Icon, type IconName } from "./Icon";
import { GO } from "./keys";
import { consequence, LABEL, MAIL_LABEL, type Verb } from "./policy";
import { VERDICT, type Tone } from "./theme";
import type { EventRow, IntelHealth, MailboxStatus, RuleFeedback, VerdictState } from "./types";
import { Badge, Chip, Empty, ErrorLine, PageTitle, Panel, Skeleton, useLoad } from "./ui";

const Ago = ({ iso }: { iso: string }) => <time dateTime={iso} title={when(iso)}>{relativeTime(iso, Date.now())}</time>;

// ---- Protection ---------------------------------------------------------------------------------------------------

const MAIL: Record<string, { tone: Tone; text: string; help: string }> = {
  connected: { tone: "ok", text: "connected", help: "New messages are read (read-only) and judged as they arrive." },
  reauth_needed: { tone: "warn", text: "sign-in needed", help: "The mail provider no longer accepts the saved sign-in. Connect again: python -m core.mailbox connect" },
  error: { tone: "bad", text: "error", help: "The last check failed. Lynceus keeps trying; see python -m core.mailbox status." },
  disconnected: { tone: "info", text: "not connected", help: "Connect a mailbox (read-only): python -m core.mailbox connect [--provider outlook]" },
  off: { tone: "info", text: "not set up", help: "Mail checking is off by default. Turn it on with LYNCEUS_GMAIL_ENABLED or LYNCEUS_OUTLOOK_ENABLED, then connect." },
};

function Guard({ icon, title, tone, state, children, ...data }: { icon: IconName; title: string; tone: Tone; state: string; children: ReactNode } & Record<`data-${string}`, string | boolean>) {
  return (
    <li className={`guard tone-${tone}`} {...data}>
      <span className="guard-icon"><Icon name={icon} weight="duotone" size={22} /></span>
      <div className="guard-body">
        <div className="guard-top"><strong>{title}</strong><Chip tone={tone}>{state}</Chip></div>
        <div className="guard-text">{children}</div>
      </div>
    </li>
  );
}

const age = (hours: number | null): string => (hours === null ? "never downloaded" : hours < 1 ? "less than an hour old" : hours < 48 ? `${Math.round(hours)} hours old` : `${Math.round(hours / 24)} days old`);

export function ProtectionPage({ api }: { api: Api }) {
  const health = useLoad(() => api.health(), [api], 5000);
  const mailbox = useLoad(() => api.mailbox(), [api], 10000);
  const intel = useLoad<IntelHealth>(() => api.intelHealth(), [api], 30000);
  const up = health.data?.status === "ok";
  const mail = MAIL[mailbox.data?.state ?? ""] ?? { tone: "info" as Tone, text: mailbox.data?.state ?? "…", help: "" };
  const m: MailboxStatus | null = mailbox.data;
  return (
    <>
      <PageTitle icon="ShieldStar" title="Protection" lead="Every guard Lynceus runs, and what each one is doing right now. Anything that is off says so, and how to turn it on." />
      <ErrorLine error={health.error ?? intel.error} />
      <Panel title="On this computer" icon="Heartbeat">
        <ul className="guards">
          <Guard icon="Cpu" title="Analysis engine" tone={up ? "ok" : health.error ? "bad" : "info"} state={up ? "running" : health.error ? "not reachable" : "checking…"} data-engine>
            Judges links, messages and files with its own rules, in a sandbox, on this computer. Monitoring by the Windows agent and the browser extension keeps running when this console is closed.
          </Guard>
          <Guard icon="EnvelopeSimple" title="Mailbox" tone={mail.tone} state={mail.text} data-mailbox>
            {mail.help}
            {m && (m.last_poll || m.analysed !== undefined) ? (
              <span className="guard-facts">
                {m.last_poll ? <span>Last check <Ago iso={m.last_poll} /></span> : null}
                {m.analysed !== undefined ? <span>{plural(m.analysed, "message")} read</span> : null}
                {Array.isArray(m.flagged) ? <span>{plural(m.flagged.length, "flagged")}</span> : null}
              </span>
            ) : null}
          </Guard>
          <Guard icon="Vault" title="Responses" tone="accent" state="proposed here">
            A flagged file or message gets a proposed response in Responses. Whether the agent waits for you (the default) or acts by itself is the agent's own setting (ResponseMode in agent.json). Nothing is ever deleted, and everything can be restored.
          </Guard>
        </ul>
      </Panel>

      <Panel title="Outside lookups" icon="Broadcast" actions={intel.data ? <span className="muted">{plural(intel.data.providers.length, "provider")}</span> : null}>
        {intel.data === null ? (intel.error ? <p className="muted">Could not be read from the core.</p> : <Skeleton lines={3} />) : intel.data.providers.length === 0 ? (
          <Empty icon="LockKey" title="None: nothing leaves this computer">No outside service is asked about anything. Lists can be turned on with LYNCEUS_INTEL_PROVIDERS (see .env.example).</Empty>
        ) : (
          <ul className="guards">
            {intel.data.providers.map((p) => (
              <Guard
                key={p.provider} icon={p.usable ? "Broadcast" : "Prohibit"} title={p.provider} tone={p.usable ? "ok" : "warn"}
                state={p.usable ? "usable" : "not usable"} data-provider={p.provider} data-usable={p.usable ? "yes" : "no"}
              >
                Sends: <strong>{p.sends}</strong>. Circuit breaker: {p.breaker.replaceAll("_", " ").toLowerCase()}{p.breaker.toLowerCase() === "closed" ? " (answering normally)" : " (paused after errors; it retries by itself)"}.
              </Guard>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Lists kept on this computer" icon="Rss" actions={<span className="muted">refresh: python -m core.intel sync</span>}>
        {intel.data === null ? (intel.error ? <p className="muted">Could not be read from the core.</p> : <Skeleton lines={2} />) : intel.data.feeds.length === 0 ? <p className="muted">No list is in use.</p> : (
          <ul className="guards">
            {intel.data.feeds.map((f) => (
              <Guard
                key={f.feed} icon="Database" title={f.feed} tone={!f.downloaded ? "warn" : f.stale ? "warn" : "ok"}
                state={!f.downloaded ? "not downloaded" : f.stale ? "out of date" : "up to date"} data-feed={f.feed} data-entries={String(f.entries)}
              >
                <span className="guard-facts"><span>{plural(f.entries, "entry", "entries")}</span><span>{age(f.age_hours)}</span></span>
              </Guard>
            ))}
          </ul>
        )}
      </Panel>
    </>
  );
}

// ---- Feedback -----------------------------------------------------------------------------------------------------

const KIND_WORDS: Record<string, string> = { URL: "a link", EMAIL: "an email", FILE: "a file" };

type Sort = "noisy" | "judged" | "name";
const SORTS: Array<{ value: Sort; label: string }> = [{ value: "noisy", label: "Noisiest first" }, { value: "judged", label: "Most judged" }, { value: "name", label: "By name" }];

export function sortRules(rules: readonly RuleFeedback[], by: Sort): RuleFeedback[] {
  const total = (r: RuleFeedback) => r.false_alarm + r.correct + r.missed;
  return [...rules].sort((a, b) =>
    by === "name" ? a.rule_id.localeCompare(b.rule_id)
      : by === "judged" ? total(b) - total(a) || a.rule_id.localeCompare(b.rule_id)
      : b.false_alarm - a.false_alarm || a.correct - b.correct || a.rule_id.localeCompare(b.rule_id));
}

export function FeedbackPage({ api }: { api: Api }) {
  const rules = useLoad(() => api.feedbackRules(), [api], 15000);
  const events = useLoad<EventRow[]>(() => api.events(undefined, 200), [api], 15000);
  const [by, setBy] = useState<Sort>("noisy");
  const firedOn = (rule: string) => (events.data ?? []).filter((e) => e.rules.includes(rule));
  return (
    <>
      <PageTitle icon="ChatCircleText" title="Feedback" lead={'What you said about verdicts ("Was this right?" on an event, "This warning is wrong" in the browser), counted per rule. A rule you often call wrong is noisy on this computer.'} />
      <ErrorLine error={rules.error} />
      <div className="segmented" role="group" aria-label="Order">
        {SORTS.map((s) => <button key={s.value} type="button" className={by === s.value ? "seg on" : "seg"} aria-pressed={by === s.value} onClick={() => setBy(s.value)}>{s.label}</button>)}
      </div>
      <Panel>
        {rules.data === null ? <Skeleton lines={4} /> : rules.data.length === 0 ? (
          <Empty icon="ChatCircleText" title="No feedback yet">Open an event and answer "Was this right?", or use "This warning is wrong" on a warning page in the browser.</Empty>
        ) : (
          <ul className="rules">
            {sortRules(rules.data, by).map((r) => {
              const judged = r.false_alarm + r.correct;
              const share = judged === 0 ? 0 : Math.round((r.false_alarm / judged) * 100);
              const recent = firedOn(r.rule_id);
              return (
                <li key={r.rule_id} className="rule" data-rule={r.rule_id} data-false-alarm={String(r.false_alarm)} data-correct={String(r.correct)} data-missed={String(r.missed)}>
                  <div className="rule-name">
                    <strong>{ruleWords(r.rule_id)}</strong>
                    <code>{r.rule_id}</code>
                  </div>
                  <dl className="rule-counts">
                    <div className="tone-bad"><dt><Icon name="ThumbsDown" size={14} />False alarm</dt><dd>{r.false_alarm}</dd></div>
                    <div className="tone-ok"><dt><Icon name="ThumbsUp" size={14} />Right</dt><dd>{r.correct}</dd></div>
                    <div className="tone-warn"><dt><Icon name="Fish" size={14} />Missed</dt><dd>{r.missed}</dd></div>
                  </dl>
                  <div className="rule-share">
                    <svg className="meter" viewBox="0 0 100 8" preserveAspectRatio="none" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={share} aria-label="Share of its judged verdicts you called false alarms">
                      <rect className="meter-track" width="100" height="8" rx="4" />
                      <rect className="meter-fill bad" width={share} height="8" rx="4" />
                    </svg>
                    <span className="muted">{judged === 0 ? "not judged yet" : `${share}% called wrong`}</span>
                  </div>
                  <div className="rule-recent">
                    {recent.length === 0 ? <span className="muted">Not in the last {events.data?.length ?? 0} events.</span> : (
                      <>
                        <span className="muted">Fired on {plural(recent.length, "recent event")}:</span>
                        {recent.slice(0, 3).map((e) => (
                          <a key={e.id} href={`#/events/${e.id}`} className="rule-event"><Badge value={e.state} size="sm" /><span className={e.host ? "mono" : undefined}>{e.host ?? KIND_WORDS[e.kind.toUpperCase()] ?? e.kind.toLowerCase()}</span></a>
                        ))}
                      </>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Panel>
    </>
  );
}

// ---- Guide --------------------------------------------------------------------------------------------------------

const VERDICT_ORDER: VerdictState[] = ["MALICIOUS", "SUSPICIOUS", "UNKNOWN", "ERROR", "BENIGN"];
const VERBS: Verb[] = ["approve", "dismiss", "restore", "restore_allow", "retry"];

export function GuidePage() {
  return (
    <>
      <PageTitle icon="BookOpenText" title="Guide" lead="What Lynceus tells you, what you can do about it, and what never leaves this computer." />
      <Panel title="The five verdicts" icon="SealCheck">
        <ul className="guide-verdicts">
          {VERDICT_ORDER.map((v) => (
            <li key={v} data-verdict={v} className={`tone-${VERDICT[v].tone}`}>
              <Badge value={v} />
              <div><strong>{VERDICT[v].headline}</strong><p>{VERDICT[v].meaning}</p></div>
            </li>
          ))}
        </ul>
        <p className="guide-note"><Icon name="Info" weight="duotone" size={16} /><span>A score adds up signs of different kinds. Signs of the same kind are capped, so many weak hints of one kind never add up to certainty. MALICIOUS needs a risk of at least 80 and strong signs of two independent kinds; SUSPICIOUS starts at 45. A message or a file is never called BENIGN: the best a clean one gets is UNKNOWN.</span></p>
      </Panel>

      <Panel title="What each response does" icon="Vault">
        <ul className="guide-responses">
          {VERBS.map((v) => (
            <li key={v} data-response={v}>
              <strong>{LABEL[v]}</strong>
              <p>{v === "restore_allow"
                ? "The agent will put the file back, and Lynceus will stop flagging this exact file for as long as you choose: 30 days, a year, or until you remove it from the allow list."
                : consequence(v, 30)}</p>
              {MAIL_LABEL[v] !== LABEL[v] ? <p className="muted">For an email: “{MAIL_LABEL[v]}”. {consequence(v, 30, "MAIL_QUARANTINE")}</p> : null}
            </li>
          ))}
        </ul>
      </Panel>

      <div className="grid">
        <Panel title="What stays on this computer" icon="LockKey">
          <ul className="guide-list">
            <li>Links, messages and files are judged here, by Lynceus's own rules, in a sandbox. Nothing is run.</li>
            <li>Outside lookups are off unless you turn them on; even then only a registered domain name is sent, never a full link, a message or a file (see Protection).</li>
            <li>Nothing is ever deleted. Quarantine moves a file to a private folder, or a message to a label or folder in your mailbox, and both come back with Restore.</li>
            <li>This console keeps your session for this tab only, and remembers one thing between visits: your theme.</li>
            <li>The audit log records every decision without file names or locations.</li>
          </ul>
        </Panel>
        <Panel title="Keyboard shortcuts" icon="Keyboard">
          <dl className="keys">
            {GO.map(([key, , label]) => <div key={key}><dt><kbd>g</kbd> <kbd>{key}</kbd></dt><dd>{label}</dd></div>)}
            <div><dt><kbd>/</kbd></dt><dd>Search events, or type a link on Analyze</dd></div>
            <div><dt><kbd>?</kbd></dt><dd>This guide</dd></div>
            <div><dt><kbd>Esc</kbd></dt><dd>Close the menu</dd></div>
          </dl>
          <p className="muted">Shortcuts never fire while you type in a field.</p>
        </Panel>
      </div>
    </>
  );
}
