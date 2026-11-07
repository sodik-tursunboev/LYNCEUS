import { AGENT_DOWN, AGENT_SLOW, parseReply, type Reply, type Request } from "./protocol";

export const HOST_NAME = "com.lynceus.agent";
export type LinkState = "up" | "down";

interface Waiting {
  resolve: (r: Reply) => void;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * One Native Messaging port to the agent. It never throws and never waits forever: a request
 * always ends in a reply, and when the host or the agent is not there that reply is an
 * `agent_unavailable` error, which the caller shows as "not protected". The port is reopened
 * after it drops, with a growing pause, and again whenever the service worker starts.
 */
export class NativeLink {
  state: LinkState = "down";
  private port: chrome.runtime.Port | null = null;
  private readonly waiting = new Map<string, Waiting>();
  private seq = 0;
  private pause = 1000;
  private retry: ReturnType<typeof setTimeout> | undefined;

  constructor(
    private readonly runtime: Pick<typeof chrome.runtime, "connectNative">,
    private readonly onState: (s: LinkState) => void = () => undefined,
    private readonly host = HOST_NAME,
  ) {}

  connect(): boolean {
    if (this.port) return true;
    try {
      const port = this.runtime.connectNative(this.host);
      port.onMessage.addListener((m: unknown) => this.onMessage(m));
      port.onDisconnect.addListener(() => this.onDisconnect(port));
      this.port = port;
      return true;
    } catch {
      this.setState("down");
      return false;
    }
  }

  /** Always resolves. A missing agent, a dropped port and a slow agent all come back as error replies. */
  request(req: Request, timeoutMs = 6000): Promise<Reply> {
    const id = `${++this.seq}-${Math.random().toString(36).slice(2, 8)}`;
    if (!this.connect() || !this.port) return Promise.resolve({ type: "error", id, error: AGENT_DOWN });
    const port = this.port;
    return new Promise<Reply>((resolve) => {
      const timer = setTimeout(() => {
        this.waiting.delete(id);
        this.setState("down");
        resolve({ type: "error", id, error: AGENT_SLOW });
      }, timeoutMs);
      this.waiting.set(id, { resolve, timer });
      try {
        port.postMessage({ v: 1, id, ...req });
      } catch {
        this.finish(id, { type: "error", id, error: AGENT_DOWN });
        this.dropPort(port);
      }
    });
  }

  private onMessage(raw: unknown): void {
    const reply = parseReply(raw);
    if (!reply || reply.id === null) return; // not ours, or not understood: ignored
    const wasAgentError = reply.type === "error" && (reply.error === AGENT_DOWN || reply.error === AGENT_SLOW);
    this.setState(wasAgentError ? "down" : "up");
    this.finish(reply.id, reply);
  }

  private onDisconnect(port: chrome.runtime.Port): void {
    // Reading lastError marks it handled; the reason is not needed and may name paths.
    void (globalThis as { chrome?: typeof chrome }).chrome?.runtime?.lastError;
    this.dropPort(port);
  }

  private dropPort(port: chrome.runtime.Port): void {
    if (this.port !== port) return;
    this.port = null;
    this.setState("down");
    for (const id of [...this.waiting.keys()]) this.finish(id, { type: "error", id, error: AGENT_DOWN });
    clearTimeout(this.retry);
    this.retry = setTimeout(() => {
      this.pause = Math.min(this.pause * 2, 30_000);
      this.connect();
    }, this.pause);
  }

  private finish(id: string, reply: Reply): void {
    const w = this.waiting.get(id);
    if (!w) return;
    clearTimeout(w.timer);
    this.waiting.delete(id);
    w.resolve(reply);
  }

  private setState(next: LinkState): void {
    if (next === "up") this.pause = 1000;
    if (this.state === next) return;
    this.state = next;
    this.onState(next);
  }
}
