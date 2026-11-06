import type { ActionRow, ActionState } from "./types";

export type Verb = "approve" | "dismiss" | "restore" | "restore_allow" | "retry";

/** Which buttons an action offers in each state. The core enforces the same rules; this only decides what to show. */
export const isMail = (kind: string | undefined): boolean => kind === "MAIL_QUARANTINE";

/** For email the allow list (by file hash) does not apply, so there is no "restore and stop flagging". */
export function verbsFor(state: ActionState, kind: string = "FILE_QUARANTINE"): Verb[] {
  if (isMail(kind) && state === "APPLIED") return ["restore"];
  switch (state) {
    case "PENDING": return ["approve", "dismiss"];
    case "APPROVED": return ["dismiss"];
    case "FAILED": return ["retry", "dismiss"];
    case "DISMISSED": return ["approve"];
    case "APPLIED": return ["restore", "restore_allow"];
    default: return [];
  }
}

export const LABEL: Record<Verb, string> = {
  approve: "Quarantine",
  dismiss: "Leave it",
  restore: "Restore",
  restore_allow: "Restore and don't flag again",
  retry: "Try again",
};

/** Says exactly what will happen, before it does. */
export function consequence(verb: Verb, days: number | null, kind: string = "FILE_QUARANTINE", provider: string | null = null): string {
  if (isMail(kind)) return mailConsequence(verb, provider);
  switch (verb) {
    case "approve":
    case "retry":
      return "The MIRAGE agent will move this file out of its folder into MIRAGE's quarantine folder. Nothing is deleted, and you can restore it here.";
    case "dismiss":
      return "The file stays where it is and MIRAGE will not propose moving it again. You can still change your mind.";
    case "restore":
      return "The agent will put the file back where it was (or beside it under a new name if that name is taken). It will be dangerous again.";
    case "restore_allow":
      return `The agent will put the file back, and MIRAGE will stop flagging this exact file ${days === null ? "until you remove it from the allow list" : `for ${days} days`}.`;
  }
}

/** Email: what will happen, before it does. Only the message's place changes; nothing is deleted or sent. */
function mailConsequence(verb: Verb, provider: string | null): string {
  const where = provider === "outlook" ? "the MIRAGE Quarantine folder" : provider === "gmail" ? "the MIRAGE-Quarantine label" : "MIRAGE's quarantine place in your mailbox";
  switch (verb) {
    case "approve":
    case "retry":
      return `MIRAGE will move this message out of your inbox into ${where}. Nothing is deleted or sent, and you can move it back here.`;
    case "dismiss":
      return "The message stays in your inbox and MIRAGE will not propose moving it again. You can still change your mind.";
    case "restore":
    case "restore_allow":
      return "MIRAGE will move the message back into your inbox. It will be dangerous again.";
  }
}

export const MAIL_LABEL: Record<Verb, string> = {
  approve: "Move out of the inbox",
  dismiss: "Leave it",
  restore: "Move back to the inbox",
  restore_allow: "Move back to the inbox",
  retry: "Try again",
};

const REASONS: Record<string, string> = {
  message_gone: "The message was no longer in the mailbox (deleted or moved by you).",
  mail_auth: "The mail provider refused the saved sign-in. Connect the mailbox again with write access.",
  mail_forbidden: "The mail provider refused the change. Check that write access is granted.",
  mail_bad_reply: "The mail provider's answer was not what was expected, so nothing is claimed done.",
  mail_unavailable: "The mail provider could not be reached after several tries.",
  no_write_access: "Write access to this mailbox is not connected.",
  mail_error: "Something unexpected stopped the move; the message was left as it is.",
  changed: "The file changed after it was checked, so MIRAGE left it alone.",
  missing: "The file was no longer there.",
  locked: "Another program was using the file.",
  link: "The file is a link or sits behind one; MIRAGE does not follow links.",
  placeholder: "The file is a cloud placeholder that is not on this computer.",
  blocked: "Another security product blocked access to the file.",
  not_file: "That was not a file.",
  bad_path: "The location was not acceptable.",
  io: "The disk refused the operation.",
  copy_failed: "The copy could not be verified, so the original was kept.",
  remove_failed: "The copy is safe but the original could not be removed.",
  unknown_file: "This agent does not know that file (it may belong to another computer or an older install).",
  no_record: "There is no quarantine record for it.",
  payload_missing: "The quarantined copy is missing.",
  payload_changed: "The quarantined copy no longer matches what was judged.",
  folder_missing: "The folder it came from no longer exists.",
  name_taken: "Its old name is in use.",
};

export const reasonText = (reason: string | null): string => (reason ? (REASONS[reason] ?? `Reason code: ${reason}`) : "");

export const GROUPS: Array<{ title: string; states: ActionState[]; empty: string }> = [
  { title: "Waiting for your decision", states: ["PENDING"], empty: "Nothing is waiting." },
  { title: "In progress", states: ["APPROVED", "RESTORE_REQUESTED"], empty: "Nothing is in progress." },
  { title: "In quarantine", states: ["APPLIED"], empty: "Nothing is in quarantine." },
  { title: "Failed", states: ["FAILED"], empty: "Nothing failed." },
  { title: "Done", states: ["DISMISSED", "RESTORED"], empty: "Nothing here yet." },
];

export const group = (actions: ActionRow[], states: ActionState[]): ActionRow[] => actions.filter((a) => states.includes(a.state));