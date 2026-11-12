import { useEffect, useRef, useState, type DragEvent, type KeyboardEvent, type RefObject } from "react";
import { ApiError, type Api } from "./api";
import {
  ROLE_TEXT, classifyPaste, destination, explainFact, formatBytes, hashRows, relativeTime, rolesPresent, sha256Hex, sizeProblem, sortLinks, sortSignals, urlParts,
} from "./analysis";
import { when } from "./format";
import { Icon, type IconName } from "./Icon";
import { categoryMeta, flagText, kindIcon, verdictMeta } from "./theme";
import type { Analysis, Anatomy, FileRow, FullSignal, HashMatch, IntelHealth, LinkRow, PageSummary } from "./types";
import { Badge, Chip, Confidence, CopyButton, Empty, ErrorLine, Gauge, Hash, PageTitle, Panel, Skeleton, Spinner, WeightBar } from "./ui";

type Mode = "url" | "email" | "file";

const MODES: Array<{ id: Mode; label: string; icon: IconName; hint: string }> = [
  { id: "url", label: "Link", icon: "Link", hint: "Paste a web address" },
  { id: "email", label: "Email", icon: "EnvelopeSimple", hint: "Drop a .eml message" },
  { id: "file", label: "File", icon: "File", hint: "Drop a document or archive" },
];

/** Made-up addresses on the reserved .test domain: analysed offline, never opened. */
const EXAMPLES: Array<{ label: string; url: string }> = [
  { label: "A trusted brand hidden in the subdomain", url: "https://paypal.com.secure-login.account-verify.test/signin?email=jane%40example.test" },
  { label: "A look-alike letter in the brand", url: "https://xn--pypal-4ve.test/verify?email=jane%40example.test" },
  { label: "A trusted name before the @", url: "https://www.paypal.com@account-check.test/login.php" },
  { label: "A trusted site that passes you on", url: "https://www.google.com/url?q=https://example.org/page" },
];

const RESPONSE: Record<string, string> = {
  NONE: "No action",
  WARN: "Warn before opening",
  BLOCK: "Block it",
  QUARANTINE: "Move to quarantine",
};

const LINK_FLAG: Record<string, string> = {
  hidden: "hidden from the reader",
  javascript: "runs script",
  invisible_text: "invisible characters in its text",
  image_link: "an image is the link",
  empty_text: "no visible text",
  conditional: "only some mail programs show it",
};

const STATUS_TONE = (s: string): "ok" | "warn" | "info" => (s === "ok" ? "ok" : s === "skipped" || s === "unsupported" ? "info" : "warn");

interface Done { id: number; what: string; result: Analysis; at: number }
type Phase = { name: "idle" } | { name: "working"; what: string; step: string } | { name: "error"; message: string };

export function AnalyzePage({ api }: { api: Api }) {
  const [mode, setMode] = useState<Mode>("url");
  const [phase, setPhase] = useState<Phase>({ name: "idle" });
  const [shown, setShown] = useState<Done | null>(null);
  const [history, setHistory] = useState<Done[]>([]);
  const [intel, setIntel] = useState<IntelHealth | null>(null);
  const counter = useRef(0);
  const heading = useRef<HTMLDivElement>(null);

  useEffect(() => { api.intelHealth().then(setIntel, () => setIntel(null)); }, [api]);
  useEffect(() => { if (shown) heading.current?.focus(); }, [shown]);

  const finish = (what: string, result: Analysis) => {
    const done: Done = { id: ++counter.current, what, result, at: Date.now() };
    setShown(done);
    setHistory((h) => [done, ...h].slice(0, 8));
    setPhase({ name: "idle" });
  };
  const fail = (e: unknown) => setPhase({ name: "error", message: e instanceof ApiError ? e.message : "That could not be analysed." });
  const busy = phase.name === "working";

  const runUrl = (url: string) => {
    setPhase({ name: "working", what: url, step: "Checking the link against the rules…" });
    api.analyzeUrl(url).then((r) => finish(url, r), fail);
  };
  const runDetonate = (url: string) => {
    setPhase({ name: "working", what: url, step: "Opening the page in the sandboxed browser (up to 30 seconds)…" });
    api.detonateUrl(url).then((r) => finish(url, r), fail);
  };
  const runEmail = async (name: string, bytes: ArrayBuffer) => {
    setPhase({ name: "working", what: name, step: "Opening the message in the sandbox…" });
    try { finish(name, await api.analyzeEmail(bytes)); } catch (e) { fail(e); }
  };
  const runFile = async (name: string, bytes: ArrayBuffer) => {
    setPhase({ name: "working", what: name, step: "Fingerprinting the file…" });
    try {
      const sha = await sha256Hex(bytes);
      setPhase({ name: "working", what: name, step: "Opening it in the sandbox…" });
      finish(name, await api.analyzeFile(name, sha, bytes));
    } catch (e) { fail(e); }
  };

  return (
    <>
      <PageTitle
        icon="MagnifyingGlass"
        title="Analyze"
        lead="Investigate a link, an email or a file. Lynceus reads it with its own rules, in a sandbox on this computer, and shows exactly why it reached its verdict."
      />
      <Panel className="intake">
        <div className="tabs" role="tablist" aria-label="What to analyze">
          {MODES.map((m) => (
            <button key={m.id} type="button" role="tab" id={`tab-${m.id}`} aria-selected={mode === m.id} aria-controls="intake-body" className={mode === m.id ? "tab on" : "tab"} onClick={() => setMode(m.id)}>
              <Icon name={m.icon} weight={mode === m.id ? "duotone" : "regular"} size={18} />
              <span>{m.label}</span>
            </button>
          ))}
        </div>
        <div id="intake-body" role="tabpanel" aria-labelledby={`tab-${mode}`} className="intake-body">
          {mode === "url" ? <UrlIntake busy={busy} onRun={runUrl} onSwitch={setMode} /> : null}
          {mode === "email" ? <EmailIntake busy={busy} onRun={runEmail} /> : null}
          {mode === "file" ? <FileIntake busy={busy} onRun={runFile} /> : null}
        </div>
        <PrivacyNote intel={intel} />
      </Panel>

      {history.length > 1 ? (
        <div className="history" aria-label="Analyses in this session">
          <span className="muted"><Icon name="ClockCounterClockwise" size={14} /> This session</span>
          {history.map((h) => (
            <button key={h.id} type="button" className={`history-item${shown?.id === h.id ? " on" : ""}`} onClick={() => setShown(h)} title={h.what}>
              <Icon name={kindIcon(h.result.type)} size={13} />
              <span className="history-what">{shortWhat(h.what)}</span>
              <Badge value={h.result.verdict.state} size="sm" />
            </button>
          ))}
        </div>
      ) : null}

      <div aria-live="polite">
        {phase.name === "working" ? (
          <Panel className="working"><Spinner label={phase.step} /><Skeleton lines={4} /></Panel>
        ) : null}
        {phase.name === "error" ? <ErrorLine error={phase.message} /> : null}
        {phase.name !== "working" && shown ? <Result done={shown} headingRef={heading} onDetonate={runDetonate} /> : null}
        {phase.name === "idle" && !shown ? (
          <Empty icon="Binoculars" title="Nothing analysed yet">
            Paste a link above, or drop a message or file. Everything stays on this computer.
          </Empty>
        ) : null}
      </div>
    </>
  );
}

const shortWhat = (s: string): string => (s.length > 38 ? `${s.slice(0, 36)}…` : s);

function PrivacyNote({ intel }: { intel: IntelHealth | null }) {
  const outside = intel?.providers ?? [];
  return (
    <p className="privacy">
      <Icon name="LockKey" weight="duotone" size={16} />
      {intel === null ? "Analysed on this computer by Lynceus's own engine."
        : outside.length === 0 ? "Analysed on this computer. No outside service is asked: nothing leaves your machine."
        : `Analysed on this computer. Outside lookups are on (${outside.map((p) => p.provider).join(", ")}); only a registered domain name is ever sent, never a full link, a message or a file.`}
    </p>
  );
}

// ---- intake ------------------------------------------------------------------------------------------------

function UrlIntake({ busy, onRun, onSwitch }: { busy: boolean; onRun: (url: string) => void; onSwitch: (m: Mode) => void }) {
  const [value, setValue] = useState("");
  const kind = classifyPaste(value);
  const go = () => { if (!busy && value.trim() && kind !== "email") onRun(value.trim()); };
  const key = (e: KeyboardEvent<HTMLInputElement>) => { if (e.key === "Enter") go(); };
  return (
    <>
      <div className="url-box">
        <Icon name="Link" weight="duotone" size={22} />
        <input
          className="url-input mono" type="text" inputMode="url" spellCheck={false} autoComplete="off" autoCapitalize="off"
          placeholder="https://… paste a link exactly as you received it" aria-label="Link to analyze" value={value}
          maxLength={8192} onChange={(e) => setValue(e.target.value)} onKeyDown={key} disabled={busy}
        />
        <button type="button" className="btn primary big" disabled={busy || !value.trim() || kind === "email"} onClick={go}>
          <Icon name="MagnifyingGlass" size={17} />Analyze
        </button>
      </div>
      {kind === "email" ? (
        <p className="hint">
          <Icon name="Info" weight="duotone" size={15} />That looks like the source of an email, not a link.
          <button type="button" className="linkish" onClick={() => onSwitch("email")}>Analyze it as an email</button>
        </p>
      ) : null}
      <div className="examples">
        <span className="muted">Try a made-up example:</span>
        {EXAMPLES.map((ex) => (
          <button key={ex.url} type="button" className="chip-btn" disabled={busy} onClick={() => { setValue(ex.url); onRun(ex.url); }}>
            <Icon name="Sparkle" size={13} />{ex.label}
          </button>
        ))}
      </div>
    </>
  );
}

function DropZone({ title, hint, accept, busy, onFile, problem }: {
  title: string; hint: string; accept?: string; busy: boolean; onFile: (f: File) => void; problem: (f: File) => string | null;
}) {
  const [over, setOver] = useState(false);
  const [complaint, setComplaint] = useState<string | null>(null);
  const take = (f: File | undefined) => {
    if (!f) return;
    const p = problem(f);
    setComplaint(p);
    if (!p) onFile(f);
  };
  const drop = (e: DragEvent<HTMLLabelElement>) => { e.preventDefault(); setOver(false); if (!busy) take(e.dataTransfer.files[0]); };
  return (
    <>
      <label
        className={`drop${over ? " over" : ""}${busy ? " disabled" : ""}`}
        onDragOver={(e) => { e.preventDefault(); if (!busy) setOver(true); }} onDragLeave={() => setOver(false)} onDrop={drop}
      >
        <Icon name="CloudArrowUp" weight="duotone" size={38} />
        <strong>{title}</strong>
        <span>{hint}</span>
        <input type="file" accept={accept} disabled={busy} onChange={(e) => { take(e.target.files?.[0]); e.target.value = ""; }} />
        <span className="btn"><Icon name="UploadSimple" size={15} />Choose a file</span>
      </label>
      {complaint ? <p className="error-line" role="alert"><Icon name="WarningOctagon" weight="fill" size={16} />{complaint}</p> : null}
    </>
  );
}

function EmailIntake({ busy, onRun }: { busy: boolean; onRun: (name: string, bytes: ArrayBuffer) => void }) {
  const [text, setText] = useState("");
  const pasted = classifyPaste(text);
  const send = () => {
    const bytes = new TextEncoder().encode(text);
    const p = sizeProblem("email", bytes.byteLength);
    if (!p) onRun("pasted message", bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer);
  };
  return (
    <>
      <DropZone
        title="Drop an email here" hint="A .eml file (in Outlook or Gmail: save or download the message). Up to 10 MB." accept=".eml,message/rfc822" busy={busy}
        problem={(f) => sizeProblem("email", f.size)} onFile={(f) => { void f.arrayBuffer().then((b) => onRun(f.name, b)); }}
      />
      <details className="paste">
        <summary><Icon name="FileText" size={15} />Or paste the message source</summary>
        <textarea
          className="mono" rows={7} spellCheck={false} value={text} onChange={(e) => setText(e.target.value)} disabled={busy}
          aria-label="Full source of the message" placeholder={"Received: …\nFrom: …\nSubject: …\n\n(the whole message, headers included)"}
        />
        <div className="row">
          <button type="button" className="btn primary" disabled={busy || pasted !== "email"} onClick={send}><Icon name="MagnifyingGlass" size={16} />Analyze message</button>
          {text.trim() && pasted !== "email" ? <span className="muted">That does not look like a full message with headers.</span> : null}
        </div>
      </details>
    </>
  );
}

function FileIntake({ busy, onRun }: { busy: boolean; onRun: (name: string, bytes: ArrayBuffer) => void }) {
  return (
    <DropZone
      title="Drop a file here" hint="Documents, PDFs, images and archives are opened in the sandbox, never on your desktop. Up to 16 MB." busy={busy}
      problem={(f) => sizeProblem("file", f.size)} onFile={(f) => { void f.arrayBuffer().then((b) => onRun(f.name, b)); }}
    />
  );
}

// ---- the result -----------------------------------------------------------------------------------------------

function Result({ done, headingRef, onDetonate }: { done: Done; headingRef: RefObject<HTMLDivElement | null>; onDetonate: (url: string) => void }) {
  const r = done.result;
  const v = r.verdict;
  const meta = verdictMeta(v.state);
  const links = r.type === "url" ? [] : r.links;
  const files = r.type === "url" ? [] : r.files;
  return (
    <div className="result">
      <section className={`hero tone-${meta.tone}`} aria-label="Verdict">
        <Gauge score={v.risk_score} state={v.state} />
        <div className="hero-main">
          <div className="eyebrow"><Icon name={kindIcon(r.type)} size={14} />{r.type === "url" ? "Link" : r.type === "email" ? "Email" : "File"} · <span className="mono">{shortWhat(done.what)}</span> · {relativeTime(new Date(done.at).toISOString(), Date.now())}</div>
          <div ref={headingRef} tabIndex={-1} className="hero-headline">
            <Icon name={meta.icon} weight="fill" size={30} />
            <h3>{meta.headline}</h3>
          </div>
          <p className="hero-meaning">{meta.meaning}</p>
          <p className="hero-why">{v.explanation}</p>
          <div className="chips">
            <Badge value={v.state} />
            <Confidence level={v.confidence} />
            <Chip tone="accent" icon="ShieldCheck">Recommended: {RESPONSE[v.recommended_response] ?? v.recommended_response}</Chip>
            {r.type === "file" && r.allow_listed ? <Chip tone="info" icon="ListChecks">on your allow list</Chip> : null}
            {r.type === "file" && r.action_id ? <Chip tone="warn" icon="Hourglass">response waiting in Responses</Chip> : null}
          </div>
        </div>
      </section>

      {r.reason ? (
        <Panel tone="warn" title="Limited analysis" icon="WarningOctagon">
          <p>Not everything could be examined ({r.reason.replaceAll("_", " ")}). That is stated, not hidden: a partial look is never a clean bill of health.</p>
        </Panel>
      ) : null}

      <div className="grid">
        <SignalsPanel signals={v.signals} />
        <div className="stack">
          {r.type === "url" && r.anatomy ? <AnatomyPanel a={r.anatomy} normalized={r.normalized_url} flags={r.flags} /> : null}
          {r.type === "email" && r.summary ? <SummaryPanel s={r.summary} /> : null}
          {r.type === "file" ? <FileSummary inspected={r.inspected} count={r.files.length} links={r.links.length} /> : null}
          {r.type === "file" ? <HashesPanel hashes={r.hashes} matches={r.hash_matches ?? []} lists={r.hash_lists ?? 0} /> : null}
          <ProvidersPanel results={v.provider_results} skipped={r.type === "url" ? r.intel_skipped : []} />
        </div>
      </div>

      {r.type === "url" && r.page ? <PagePanel p={r.page} /> : null}
      {r.type === "url" && !r.page && r.anatomy && /^https?$/.test(r.anatomy.scheme) ? <SandboxOffer onRun={() => onDetonate(done.what)} /> : null}

      {links.length > 0 ? <LinksPanel links={links} /> : null}
      {files.length > 0 ? <FilesPanel files={files} /> : null}

      <Panel title="Evidence" icon="Fingerprint" actions={<span className="muted">{r.evidence.length} item{r.evidence.length === 1 ? "" : "s"}</span>}>
        {r.evidence.length === 0 ? <p className="muted">No evidence items.</p> : (
          <ul className="evidence">
            {r.evidence.map((x) => (
              <li key={x.id}>
                <Chip icon="Hash">{x.kind}</Chip>
                <span className="evidence-text">{x.summary}</span>
                {x.sha256 ? <><Hash value={x.sha256} /><CopyButton text={x.sha256} label="Copy the full hash" /></> : null}
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <footer className="result-foot">
        <span><Icon name="Cpu" size={14} />engine {v.engine_version} · ruleset <span className="mono">{v.ruleset_version}</span> · {when(v.created_at)}</span>
        {r.persisted
          ? <a href={`#/events/${v.id}`}><Icon name="Check" size={14} />Recorded in Events</a>
          : <span><Icon name="CircleDashed" size={14} />Not recorded (no database is configured)</span>}
      </footer>
    </div>
  );
}

const MARKER_TEXT: Record<string, string> = {
  devtools_trap: "traps or watches for developer tools",
  key_block: "blocks keyboard shortcuts",
  context_block: "blocks the right-click menu",
  webdriver_check: "checks for an automated browser",
  decoded_writer: "writes decoded content into the page",
  heavy_decoding: "decodes a lot of hidden text",
};
const PAGE_STATUS: Record<string, string> = {
  ok: "Opened",
  partial: "Opened, but it did not finish loading",
  dead: "Could not be opened (gone, or not reachable)",
  error: "The sandboxed browser could not run",
};

/** D1: the opened page. The screenshot was re-encoded in the parser sandbox and is not stored. */
function PagePanel({ p }: { p: PageSummary }) {
  const asks = p.password_fields > 0
    ? `a password (${p.password_fields} field${p.password_fields === 1 ? "" : "s"})`
    : p.forms > 0 ? `${p.forms} form${p.forms === 1 ? "" : "s"}, no password` : "nothing";
  return (
    <Panel title="The page, opened in the sandbox" icon="Flask" actions={<span className="muted">{(p.elapsed_ms / 1000).toFixed(1)} s</span>}>
      <ul className="facts">
        <li><strong>{PAGE_STATUS[p.status] ?? p.status}</strong>{p.http_status ? ` · HTTP ${p.http_status}` : ""}{p.error ? ` · ${p.error.replaceAll("_", " ")}` : ""}</li>
        {p.chain_hosts.length > 0 ? <li>Went through <span className="mono">{p.chain_hosts.join(" → ")}</span></li> : null}
        {p.title ? <li>Title: <strong>{p.title}</strong></li> : null}
        <li>Asks for {asks}</li>
        {p.markers.length > 0 ? <li>Hides from analysis: it {p.markers.map((m) => MARKER_TEXT[m] ?? m).join("; ")}</li> : null}
        {p.downloads.length > 0 ? <li>Tried to download {p.downloads.map((d) => `.${d || "?"}`).join(", ")} (nothing was kept)</li> : null}
        <li>Contacted {p.hosts_contacted} host{p.hosts_contacted === 1 ? "" : "s"}</li>
        {p.tls_valid_from ? <li>Certificate issued {new Date(p.tls_valid_from * 1000).toISOString().slice(0, 10)}</li> : null}
      </ul>
      {p.screenshot_jpeg ? <img className="page-shot" src={`data:image/jpeg;base64,${p.screenshot_jpeg}`} alt={`What the page showed${p.title ? `: ${p.title}` : ""}`} /> : null}
      <p className="muted">Opened in a throwaway browser, from this computer's internet connection. Nothing was typed or sent to the page, and the screenshot is not stored.</p>
    </Panel>
  );
}

function SandboxOffer({ onRun }: { onRun: () => void }) {
  return (
    <Panel title="Look at the page itself" icon="Flask">
      <p>The address alone often says nothing. Lynceus can open the page in a locked-down browser that is thrown away afterwards and judge what the page shows: a brand's sign-in form on someone else's site, where a form sends your password, code that hides from analysts.</p>
      <p className="muted">The page is visited from this computer's internet connection, so whoever runs it sees your IP address. Nothing is typed into it.</p>
      <button type="button" className="btn primary" onClick={onRun}><Icon name="Flask" size={16} />Open in sandbox</button>
    </Panel>
  );
}

export type SignalLike = Pick<FullSignal, "rule_id" | "category" | "weight" | "description" | "attack">;

export function SignalsPanel({ signals }: { signals: SignalLike[] }) {
  const sorted = sortSignals(signals);
  return (
    <Panel title="Why" icon="ListMagnifyingGlass" actions={<span className="muted">{signals.length} sign{signals.length === 1 ? "" : "s"}</span>} className="signals-panel">
      {sorted.length === 0 ? <Empty icon="SealCheck" title="No sign of phishing fired">The rules found nothing. That is not proof of safety.</Empty> : (
        <ol className="signals">
          {sorted.map((s) => {
            const cat = categoryMeta(s.category);
            return (
              <li key={s.rule_id}>
                <div className="signal-icon" title={cat.label}><Icon name={cat.icon} weight="duotone" size={22} /></div>
                <div className="signal-body">
                  <div className="signal-top">
                    <span className="mono signal-id">{s.rule_id}</span>
                    <Chip>{cat.label}</Chip>
                    {s.attack ? <Chip tone="accent" icon="Tag">ATT&amp;CK {s.attack}</Chip> : null}
                  </div>
                  <p>{s.description}</p>
                </div>
                <WeightBar weight={s.weight} />
              </li>
            );
          })}
        </ol>
      )}
    </Panel>
  );
}

function AnatomyPanel({ a, normalized, flags }: { a: Anatomy; normalized: string | null; flags: string[] }) {
  const parts = urlParts(a);
  const goes = destination(a);
  return (
    <Panel title="Anatomy of the link" icon="TreeStructure" actions={normalized ? <CopyButton text={normalized} label="Copy the cleaned-up link" /> : null}>
      <div className="anatomy mono" aria-label="The link, cut into its parts">
        {parts.map((p, i) => <span key={i} className={`part role-${p.role}`}>{p.text}</span>)}
      </div>
      {goes ? (
        <p className="goes"><Icon name="Crosshair" weight="duotone" size={18} /><span>The browser will connect to <strong className="mono">{goes}</strong>{a.private_suffix ? " (a name anyone can register under a shared host)" : ""}.</span></p>
      ) : null}
      <details className="legend-wrap">
        <summary><Icon name="Info" weight="duotone" size={15} />What the parts mean</summary>
        <dl className="legend">
          {rolesPresent(parts).map((role) => (
            <div key={role}><dt><i className={`swatch role-${role}`} />{ROLE_TEXT[role].label}</dt><dd>{ROLE_TEXT[role].help}</dd></div>
          ))}
        </dl>
      </details>
      {flags.length > 0 ? (
        <ul className="flags">{flags.map((f) => <li key={f}><Icon name="Info" weight="duotone" size={15} />This link {flagText(f)}.</li>)}</ul>
      ) : null}
    </Panel>
  );
}

function SummaryPanel({ s }: { s: NonNullable<Extract<Analysis, { type: "email" }>["summary"]> }) {
  const tile = (icon: IconName, label: string, value: string) => (
    <div className="tile"><Icon name={icon} weight="duotone" size={20} /><b>{value}</b><span>{label}</span></div>
  );
  return (
    <Panel title="The message" icon="EnvelopeSimple">
      <div className="tiles">
        {tile("HardDrives", "size", formatBytes(s.size))}
        {tile("TreeStructure", "parts", String(s.parts))}
        {tile("Paperclip", "attachments", String(s.attachments))}
        {tile("Link", "links", `${s.links_analyzed}/${s.links}`)}
      </div>
      {s.relative_links_skipped > 0 ? <p className="muted">{s.relative_links_skipped} relative link(s) have no address of their own and were not checked.</p> : null}
      {s.limits_hit.length > 0 ? <p className="note"><Icon name="Warning" weight="fill" size={15} />Limits reached: {s.limits_hit.join(", ")}.</p> : null}
      {s.defects.length > 0 ? <p className="note"><Icon name="Warning" weight="fill" size={15} />Malformed in places: {s.defects.join(", ")}.</p> : null}
    </Panel>
  );
}

function FileSummary({ inspected, count, links }: { inspected: boolean; count: number; links: number }) {
  return (
    <Panel title="The file" icon="File">
      <div className="tiles">
        <div className="tile"><Icon name={inspected ? "Eye" : "EyeSlash"} weight="duotone" size={20} /><b>{inspected ? "opened" : "not opened"}</b><span>in the sandbox</span></div>
        <div className="tile"><Icon name="Paperclip" weight="duotone" size={20} /><b>{count}</b><span>inside it</span></div>
        <div className="tile"><Icon name="Link" weight="duotone" size={20} /><b>{links}</b><span>links found</span></div>
      </div>
      {!inspected ? <p className="note"><Icon name="Warning" weight="fill" size={15} />Only its name, size and fingerprint were judged. Its contents were not examined.</p> : null}
    </Panel>
  );
}

/** The file's fingerprints, computed here, and whether any is on a known-bad list kept on this machine. */
function HashesPanel({ hashes, matches, lists }: { hashes: Record<string, string> | undefined; matches: HashMatch[]; lists: number }) {
  const rows = hashRows(hashes);
  if (rows.length === 0) return null;
  const bad = matches.length > 0;
  return (
    <Panel title="Fingerprints" icon="Fingerprint" tone={bad ? "bad" : undefined}>
      <ul className="hash-list">
        {rows.map((h) => (
          <li key={h.algorithm}>
            <Chip>{h.label}</Chip>
            <span className="mono hash-value" title={h.value}>{h.value}</span>
            <CopyButton text={h.value} label={`Copy the ${h.label} hash`} />
          </li>
        ))}
      </ul>
      {bad ? (
        <p className="note hash-hit"><Icon name="Skull" weight="fill" size={16} />
          Known malware: {matches.map((m) => `${m.where === "file" ? "this file" : "an entry inside it"} matches the ${m.algorithm.toUpperCase()} list “${m.source}”`).join("; ")}.</p>
      ) : (
        <p className="muted hash-clear"><Icon name="Hash" weight="duotone" size={15} />Not on any of the {lists} known-bad list{lists === 1 ? "" : "s"} kept here. That is not a sign of safety: new malware is on no list yet.</p>
      )}
    </Panel>
  );
}

function ProvidersPanel({ results, skipped }: { results: Analysis["verdict"]["provider_results"]; skipped: Array<{ provider: string; reason: string }> }) {
  return (
    <Panel title="Outside opinions" icon="Cloud">
      {results.length === 0 && skipped.length === 0 ? (
        <p className="muted">No outside service was asked. This is the normal offline setting.</p>
      ) : (
        <ul className="providers">
          {results.map((p, i) => (
            <li key={i}>
              <span className="provider-name">{p.provider}</span>
              {p.state ? <Badge value={p.state} size="sm" /> : <Chip tone={p.status === "OK" ? "ok" : "warn"}>{p.status.replaceAll("_", " ").toLowerCase()}</Chip>}
              <span className="muted">{p.latency_ms} ms · {p.provenance}</span>
            </li>
          ))}
          {skipped.map((p, i) => <li key={`s${i}`}><span className="provider-name">{p.provider}</span><Chip>not asked</Chip><span className="muted">{p.reason}</span></li>)}
        </ul>
      )}
    </Panel>
  );
}

function LinksPanel({ links }: { links: LinkRow[] }) {
  const sorted = sortLinks(links);
  return (
    <Panel title="Links inside" icon="Link" actions={<span className="muted">{links.length} found</span>}>
      <div className="table-wrap">
        <table className="data">
          <thead><tr><th>Where it goes</th><th>Verdict</th><th>Score</th><th>Signs</th><th>Notes</th></tr></thead>
          <tbody>
            {sorted.map((l, i) => (
              <tr key={i}>
                <td>
                  <div className="cell-host"><Icon name={kindIcon(l.kind)} weight="duotone" size={16} /><strong className="mono">{l.host ?? "no address"}</strong></div>
                  {l.normalized_url ? <div className="cell-url mono" title={l.normalized_url}>{l.normalized_url}</div> : null}
                </td>
                <td>{l.state ? <Badge value={l.state} size="sm" /> : <span className="muted">not analysed</span>}</td>
                <td className="mono">{l.risk_score ?? "–"}</td>
                <td><span className="chips">{l.rules.slice(0, 4).map((r) => <Chip key={r}>{r.split(".").pop()?.replaceAll("_", " ")}</Chip>)}</span></td>
                <td><span className="chips">{l.flags.map((f) => <Chip key={f} tone="warn">{LINK_FLAG[f] ?? f.replaceAll("_", " ")}</Chip>)}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function FilesPanel({ files }: { files: FileRow[] }) {
  return (
    <Panel title="Attachments and contents" icon="Paperclip" actions={<span className="muted">{files.length} examined</span>}>
      <ul className="files">
        {files.map((f, i) => (
          <li key={i}>
            <Icon name={kindIcon(f.kind)} weight="duotone" size={22} />
            <div>
              <div className="file-top"><strong>{f.kind.replaceAll("_", " ")}</strong><Chip tone={STATUS_TONE(f.status)}>{f.status.replaceAll("_", " ")}</Chip><span className="muted mono">part {f.part}</span></div>
              {f.facts.length > 0 ? (
                <ul className="facts">
                  {f.facts.map((x, j) => {
                    const help = explainFact(x);
                    return <li key={j}>{help ? <><strong>{x}</strong><span className="muted"> — {help}</span></> : x}</li>;
                  })}
                </ul>
              ) : <p className="muted">Nothing notable.</p>}
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
