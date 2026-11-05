import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { ApiError } from "./api";

/** Everything from the core is shown as text: React escapes it, and nothing here sets HTML. */
export const Badge = ({ value }: { value: string }) => <span className={`badge ${value}`}>{value.replaceAll("_", " ")}</span>;

export const Hash = ({ value }: { value: string }) => <span className="mono" title={value}>{value.slice(0, 12)}</span>;

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
  children?: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!open) {
    return <button className={props.danger ? "danger" : ""} onClick={() => setOpen(true)}>{props.label}</button>;
  }
  return (
    <div className="confirm" role="group" aria-label={props.label}>
      <p>{props.explain}</p>
      {props.children}
      <div className="row">
        <button
          className="primary"
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
        <button disabled={busy} onClick={() => { setOpen(false); setError(null); }}>Cancel</button>
      </div>
      {error ? <p className="error" role="alert">{error}</p> : null}
    </div>
  );
}

export const ErrorLine = ({ error }: { error: string | null }) => (error ? <p className="error" role="alert">{error}</p> : null);