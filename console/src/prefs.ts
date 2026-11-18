// The one thing the console keeps in this browser between visits (UI2): the theme you chose. One key, one of three
// words, never anything else; the session itself stays in sessionStorage (auth.ts). static/theme.js applies the
// same choice before the first paint, so the page never flashes the other theme.
export type ThemeChoice = "system" | "dark" | "light";

export const THEME_KEY = "lynceus.theme";
export const THEME_CHOICES: ReadonlyArray<{ value: ThemeChoice; label: string }> = [
  { value: "system", label: "System" },
  { value: "dark", label: "Dark" },
  { value: "light", label: "Light" },
];

type Store = Pick<Storage, "getItem" | "setItem" | "removeItem">;

/** The browser's store, or null where it is refused (a locked-down profile): the choice then lasts for the page. */
export function browserStore(): Store | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

/** Anything but "dark" or "light" (nothing stored, a value from elsewhere) means: follow the system. */
export function readTheme(store: Pick<Store, "getItem"> | null): ThemeChoice {
  try {
    const value = store?.getItem(THEME_KEY);
    return value === "dark" || value === "light" ? value : "system";
  } catch {
    return "system";
  }
}

export function writeTheme(store: Store | null, choice: ThemeChoice): void {
  try {
    if (choice === "system") store?.removeItem(THEME_KEY);
    else store?.setItem(THEME_KEY, choice);
  } catch {
    // refused: the choice still holds until the page is closed
  }
}

/** `data-theme` on <html> overrides the system setting; without it the stylesheet follows the system. */
export function applyTheme(root: Pick<HTMLElement, "setAttribute" | "removeAttribute">, choice: ThemeChoice): void {
  if (choice === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", choice);
}
