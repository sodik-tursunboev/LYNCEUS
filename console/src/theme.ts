import type { IconName } from "./icons.generated";
import type { ActionState, VerdictState } from "./types";

/** The colour family a thing belongs to. Colour never carries meaning alone: every use also has an icon and words. */
export type Tone = "bad" | "warn" | "ok" | "info" | "accent";

export interface VerdictMeta { icon: IconName; tone: Tone; headline: string; meaning: string }

export const VERDICT: Record<VerdictState, VerdictMeta> = {
  MALICIOUS: {
    icon: "Skull", tone: "bad", headline: "This looks like phishing or malware",
    meaning: "Several independent signs point the same way. Do not open it, enter anything into it or forward it.",
  },
  SUSPICIOUS: {
    icon: "Warning", tone: "warn", headline: "This has signs of phishing",
    meaning: "Some signs of an attack, but not enough to be sure. Treat it with care and check where it really leads.",
  },
  BENIGN: {
    icon: "SealCheck", tone: "ok", headline: "Nothing wrong was found",
    meaning: "An official site of a known brand. That describes the address, not every page that could be behind it.",
  },
  UNKNOWN: {
    icon: "Question", tone: "info", headline: "Not enough to say either way",
    meaning: "No rule fired, or too little to decide. Unknown is not safe: it only means MIRAGE has no opinion.",
  },
  ERROR: {
    icon: "WarningOctagon", tone: "info", headline: "The analysis did not finish",
    meaning: "Something failed while looking at it. A failed check is never a statement that it is safe.",
  },
};

export const verdictMeta = (state: string): VerdictMeta => VERDICT[state as VerdictState] ?? VERDICT.UNKNOWN;

/** Signal categories (see rules/): what kind of sign it is. */
export const CATEGORY: Record<string, { icon: IconName; label: string }> = {
  impersonation: { icon: "Detective", label: "Impersonation" },
  deception: { icon: "EyeSlash", label: "Deception" },
  credential: { icon: "Key", label: "Credential theft" },
  redirect: { icon: "ArrowBendUpRight", label: "Redirect" },
  obfuscation: { icon: "ArrowsSplit", label: "Obfuscation" },
  host: { icon: "Globe", label: "Host" },
  structure: { icon: "TreeStructure", label: "Structure" },
  scheme: { icon: "Code", label: "Scheme" },
  sender: { icon: "UserCircle", label: "Sender" },
  authentication: { icon: "ShieldSlash", label: "Authentication" },
  attachment: { icon: "Paperclip", label: "Attachment" },
  active_content: { icon: "Lightning", label: "Active content" },
  content: { icon: "FileText", label: "Content" },
  code_behavior: { icon: "Code", label: "What the code does" },
  evasion: { icon: "ShieldSlash", label: "Evasion" },
  persistence: { icon: "ArrowsClockwise", label: "Stays on the computer" },
  known_bad: { icon: "Skull", label: "Known malware" },
};

/** A category, or a category of a link inside a message ("link.impersonation"): the same icon, said as "in a link". */
export function categoryMeta(category: string): { icon: IconName; label: string } {
  const dot = category.indexOf(".");
  const base = dot >= 0 ? category.slice(dot + 1) : category;
  const known = CATEGORY[base];
  if (!known) return { icon: "Tag", label: category.replaceAll("_", " ").replace(".", " · ") };
  return dot >= 0 ? { icon: known.icon, label: `${known.label} (in a link)` } : known;
}

/** What was analysed (an artifact or a link inside a message). */
export const KIND_ICON: Record<string, IconName> = {
  URL: "Link", EMAIL: "EnvelopeSimple", FILE: "File", url: "Link", email: "EnvelopeSimple", file: "File",
  a: "Link", area: "Link", form: "Stamp", iframe: "Globe", script: "Code", meta_refresh: "ArrowBendUpRight",
  text: "TextAa", pdf_uri: "FilePdf", qr: "QrCode", image: "Image", archive: "FileZip", pdf: "FilePdf",
  code: "Code", content: "Code",
};

export const kindIcon = (kind: string): IconName => KIND_ICON[kind] ?? "File";

export const ACTION_TONE: Record<ActionState, Tone> = {
  PENDING: "warn", APPROVED: "accent", APPLIED: "ok", DISMISSED: "info", FAILED: "bad",
  RESTORE_REQUESTED: "accent", RESTORED: "ok",
};

export const ACTION_ICON: Record<ActionState, IconName> = {
  PENDING: "Hourglass", APPROVED: "ArrowRight", APPLIED: "Vault", DISMISSED: "X", FAILED: "WarningOctagon",
  RESTORE_REQUESTED: "ArrowUUpLeft", RESTORED: "Check",
};

/** Plain words for the flags the URL parser raises (see core/urls/parse.py). */
export const FLAG_TEXT: Record<string, string> = {
  SCHEME_ASSUMED: "had no scheme, so https was assumed",
  REFANGED: "was written in a defanged form (hxxp, [.]) and was restored",
  WHITESPACE_TRIMMED: "had spaces around it that were trimmed",
  INTERIOR_WHITESPACE_REMOVED: "had a tab or line break inside it",
  CONTROL_CHARS: "contains control characters",
  INVISIBLE_CHARS: "contains invisible characters (zero-width or text-direction marks)",
  BACKSLASH: "uses backslashes where a browser would read slashes",
  TRAILING_DOT: "the host ends with a dot",
  DEFAULT_PORT_ELIDED: "named the default port explicitly",
  DOUBLE_ENCODED: "is percent-encoded twice, which hides what it says",
  HOST_PERCENT_ENCODED: "the host name is percent-encoded",
  USERINFO: "has a user name in front of the host: the browser ignores everything before the @",
  IDN: "the host uses non-ASCII letters",
  PUNYCODE: "the host contains an international (xn--) label",
  IP_OBFUSCATED: "writes an IP address in a disguised form",
  IPV4_MAPPED: "an IPv4 address written in IPv6 form",
  NON_HTTP_SCHEME: "is not a web address",
  DANGEROUS_SCHEME: "uses a scheme that runs code or reads local files",
};

export const flagText = (flag: string): string => FLAG_TEXT[flag] ?? flag.toLowerCase().replaceAll("_", " ");
