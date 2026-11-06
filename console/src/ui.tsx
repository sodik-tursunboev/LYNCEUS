import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { ApiError } from "./api";
import { GAUGE_LENGTH, GAUGE_RADIUS, STATES, confidenceBars, gaugeFill, scoreBand, segments, verdictCounts } from "./analysis";
import { Icon, type IconName } from "./Icon";
import { ACTION_ICON, ACTION_TONE, verdictMeta, type Tone } from "./theme";
import type { ActionState, VerdictState } from "./types";

/** Everything from the core is shown as text: React escapes it, and nothing here sets HTML. */

const isAction = (v: string): v is ActionState => v in ACTION_TONE;

/** A verdict or a response state: icon, colour AND words, so it reads without the colour. */
export function Badge({ value, size = "md" }: { value: string; size?: "sm" | "md" }) {
  const tone: Tone = isAction(value) ? ACTION_TONE[value] : verdictMeta(value).tone;
  const icon: IconName = isAction(value) ? ACTION_ICON[value] : verdictMeta(value).icon;
  return (
    <span className={`badge tone-${tone} badge-${size}`}>
      <Icon name={icon} weight="fill" size={size === "sm" ? 12 : 14} />
      {value.replaceAll("_", " ")}
    </span>
  );
}

export const Hash = ({ value, chars = 12 }: { value: string; chars?: number }) => <span className="mono hash" title={value}>{value.slice(0, chars)}</span>;

/** Copies text, and says so. The text itself is data, never markup. */
export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (!done) return;
    const t = setTimeout(() => setDone(false), 1600);
    return () => clearTimeout(t);
  }, [done]);
  return (
    <button
      type="button"
      className="icon-btn"
      aria-label={done ? "Copied" : label}
      title={done ? "Copied" : label}
      onClick={() => { void navigator.clipboard?.writeText(text).then(() => setDone(true), () => undefined); }}
    >
      <Icon name={done ? "Check" : "Copy"} size={14} />
    </button>
  );
}

export function Panel({ title, icon, actions, children, tone, className }: {
  title?: string;
  icon?: IconName;
  actions?: ReactNode;
  children: ReactNode;
  tone?: Tone;
  className?: string;
}) {
  return (
    <section className={`panel${tone ? ` tone-${tone}` : ""}${className ? ` ${className}` : ""}`}>
      {title ? (
        <header className="panel-head">
          <h3>{icon ? <Icon name={icon} weight="duotone" size={18} /> : null}{title}</h3>
          {actions ? <div className="panel-actions">{actions}</div> : null}
        </header>
      ) : null}
      {children}
    </section>
  );
}

export function PageTitle({ icon, title, lead, actions }: { icon: IconName; title: string; lead?: string; actions?: ReactNode }) {
  return (
    <div className="page-title">
      <div className="page-title-mark"><Icon name={icon} weight="duotone" size={26} /></div>
      <div className="page-title-text">
        <h2>{title}</h2>
        {lead ? <p>{lead}</p> : null}
      </div>
      {actions ? <div className="page-title-actions">{actions}</div> : null}
    </div>
  );
}

export function Empty({ icon, title, children }: { icon: IconName; title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <Icon name={icon} weight="duotone" size={34} />
      <strong>{title}</strong>
      {children ? <p>{children}</p> : null}
    </div>
  );
}

export const Chip = ({ children, tone = "info", icon }: { children: ReactNode; tone?: Tone; icon?: IconName }) => (
  <span className={`chip tone-${tone}`}>{icon ? <Icon name={icon} size={12} /> : null}{children}</span>
);

export function Stat({ icon, label, value, note, tone = "accent", href }: {
  icon: IconName;
  label: string;
  value: ReactNode;
  note?: ReactNode;
  tone?: Tone;
  href?: string;
}) {
  const body = (
    <>
      <div className="stat-icon"><Icon name={icon} weight="duotone" size={22} /></div>
      <div className="stat-body">
        <div className="stat-label">{label}</div>
        <div className="stat-value">{value}</div>
        {note ? <div className="stat-note">{note}</div> : null}
      </div>
    </>
  );
  return href ? <a className={`stat tone-${tone}`} href={href}>{body}</a> : <div className={`stat tone-${tone}`}>{body}</div>;
}

/** The risk ring. A missing score is an empty ring labelled "not scored", never a zero. */
export function Gauge({ score, state, size = 156 }: { score: number | null; state: string; size?: number }) {
  const tone = verdictMeta(state).tone;
  const [shown, setShown] = useState(0);
  useEffect(() => {
    // a timer, not requestAnimationFrame: the ring must fill even in a tab the browser is not painting
    const id = setTimeout(() => setShown(gaugeFill(score)), 40);
    return () => clearTimeout(id);
  }, [score]);
  return (
    <figure className={`gauge tone-${tone} band-${scoreBand(score)}`} aria-label={score === null ? "Risk score: not scored" : `Risk score ${score} out of 100`}>
      <svg viewBox="0 0 140 140" width={size} height={size} aria-hidden="true">
        <circle className="gauge-ticks" cx="70" cy="70" r="65" fill="none" strokeWidth="3" strokeDasharray="1.2 6.8" />
        <circle className="gauge-track" cx="70" cy="70" r={GAUGE_RADIUS} fill="none" strokeWidth="9" />
        <circle
          className="gauge-arc" cx="70" cy="70" r={GAUGE_RADIUS} fill="none" strokeWidth="9" strokeLinecap="round"
          transform="rotate(-90 70 70)" strokeDasharray={`${shown} ${GAUGE_LENGTH}`}
        />
      </svg>
      <figcaption className="gauge-center">
        <span className="gauge-num">{score ?? "–"}</span>
        <span className="gauge-cap">{score === null ? "not scored" : "risk of 100"}</span>
      </figcaption>
    </figure>
  );
}

/** A sign's weight (0 to 1) as a small bar with its number, readable without the bar. */
export function WeightBar({ weight }: { weight: number }) {
  const pct = Math.round(Math.min(1, Math.max(0, weight)) * 100);
  return (
    <span className="weight">
      <svg className="meter" viewBox="0 0 100 8" preserveAspectRatio="none" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} aria-label="How strongly this counts">
        <rect className="meter-track" width="100" height="8" rx="4" />
        <rect className="meter-fill" width={pct} height="8" rx="4" />
      </svg>
      <span className="mono weight-num">{weight.toFixed(2)}</span>
    </span>
  );
}

export function Confidence({ level }: { level: string }) {
  const bars = confidenceBars(level);
  return (
    <span className="confidence" title={`Confidence: ${level.toLowerCase()}`}>
      <span className="bars" aria-hidden="true">{[1, 2, 3].map((i) => <i key={i} className={i <= bars ? "on" : ""} />)}</span>
      {level.toLowerCase()} confidence
    </span>
  );
}

/** How the verdicts split, as one segmented bar and a legend that also gives the numbers. */
export function Distribution({ items }: { items: Array<{ state: string }> }) {
  const counts = verdictCounts(items);
  const total = items.length;
  return (
    <div className="distribution">
      <svg className="dist-bar" viewBox="0 0 100 6" preserveAspectRatio="none" role="img" aria-label={STATES.map((s) => `${counts[s]} ${s.toLowerCase()}`).join(", ")}>
        {segments(counts).map((seg) => (
          <rect key={seg.state} className={`tone-${verdictMeta(seg.state).tone}`} x={seg.x} width={seg.width} height="6" rx="1.2" />
        ))}
        {total === 0 ? <rect className="dist-empty" width="100" height="6" rx="1.2" /> : null}
      </svg>
      <ul className="dist-legend">
        {STATES.map((s: VerdictState) => (
          <li key={s} className={`tone-${verdictMeta(s).tone}`}><Icon name={verdictMeta(s).icon} weight="fill" size={13} /><span>{s.toLowerCase()}</span><b>{counts[s]}</b></li>
        ))}
      </ul>
    </div>
  );
}

export const Skeleton = ({ lines = 3 }: { lines?: number }) => (
  <div className="skeleton" aria-hidden="true">{Array.from({ length: lines }, (_, i) => <i key={i} className={`sk-${Math.min(i, 5)}`} />)}</div>
);

export const Spinner = ({ label }: { label?: string }) => (
  <span className="spinner" role="status"><Icon name="CircleNotch" size={18} />{label ? <span>{label}</span> : null}</span>
);

export function useLoad<T>(load: () => Promise<T>, deps: unknown[], everyMs = 0): { data: T | null; error: string | null; reload: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;
  useEffect(() => {
    let live = true;
    const run = () =>
      loadRef.current().then(
        (value) => { if (live) { setData(value); setError(null); } },
        (e: unknown) => { if (live) setError(e instanceof ApiError ? e.message : "Something went wrong."); },
      );
    void run();
    const timer = everyMs > 0 ? setInterval(() => void run(), everyMs) : undefined;
    return () => { live = false; if (timer) clearInterval(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick, everyMs]);
  return { data, error, reload: useCallback(() => setTick((t) => t + 1), []) };
}

/** A button that first says what it will do, then needs a second click. */
export function ConfirmButton(props: {
  label: string;
  explain: string;
  onConfirm: () => Promise<void>;
  danger?: boolean;
  icon?: IconName;
  children?: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!open) {
    return (
      <button type="button" className={props.danger ? "btn danger" : "btn"} onClick={() => setOpen(true)}>
        {props.icon ? <Icon name={props.icon} size={15} /> : null}{props.label}
      </button>
    );
  }
  return (
    <div className="confirm" role="group" aria-label={props.label}>
      <p><Icon name="Info" weight="duotone" size={16} />{props.explain}</p>
      {props.children}
      <div className="row">
        <button
          type="button"
          className="btn primary"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            props.onConfirm().then(
              () => { setBusy(false); setOpen(false); setError(null); },
              (e: unknown) => { setBusy(false); setError(e instanceof ApiError ? e.message : "That did not work."); },
            );
          }}
        >
          Confirm: {props.label}
        </button>
        <button type="button" className="btn" disabled={busy} onClick={() => { setOpen(false); setError(null); }}>Cancel</button>
      </div>
      {error ? <p className="error" role="alert">{error}</p> : null}
    </div>
  );
}

export const ErrorLine = ({ error }: { error: string | null }) =>
  error ? <p className="error-line" role="alert"><Icon name="WarningOctagon" weight="fill" size={16} />{error}</p> : null;
