export type ThemeId =
  | "obsidian-cyber"
  | "ciphergenx-gold"
  | "synthwave-crimson"
  | "matrix-stealth"
  | "arctic-titanium";

export interface ThemeOption {
  id: ThemeId;
  name: string;
  subtitle: string;
  swatchPrimary: string;
  swatchSecondary: string;
}

export const THEMES: ThemeOption[] = [
  {
    id: "obsidian-cyber",
    name: "Obsidian Cyber",
    subtitle: "Void + Neon Cyan / Violet",
    swatchPrimary: "#00F0FF",
    swatchSecondary: "#8B5CF6",
  },
  {
    id: "ciphergenx-gold",
    name: "CipherGenX Carbon",
    subtitle: "Matte Carbon + Liquid Gold / Emerald",
    swatchPrimary: "#F59E0B",
    swatchSecondary: "#10B981",
  },
  {
    id: "synthwave-crimson",
    name: "Neon Synthwave",
    subtitle: "Midnight + Hot Magenta / Cyan",
    swatchPrimary: "#FF2E93",
    swatchSecondary: "#00F0FF",
  },
  {
    id: "matrix-stealth",
    name: "Matrix Ghost",
    subtitle: "Pitch Black + Phosphor Emerald",
    swatchPrimary: "#00FF88",
    swatchSecondary: "#06B6D4",
  },
  {
    id: "arctic-titanium",
    name: "Arctic Titanium",
    subtitle: "Nordic Slate + Frost Blue / Indigo",
    swatchPrimary: "#38BDF8",
    swatchSecondary: "#818CF8",
  },
];

const STORAGE_KEY = "cipherpass_theme_v1";

export function loadSavedTheme(): ThemeId {
  try {
    const saved = localStorage.getItem(STORAGE_KEY) as ThemeId | null;
    if (saved && THEMES.some((t) => t.id === saved)) {
      return saved;
    }
  } catch {
    // ignore storage restrictions
  }
  return "obsidian-cyber";
}

export function applyTheme(themeId: ThemeId): void {
  document.documentElement.setAttribute("data-theme", themeId);
  try {
    localStorage.setItem(STORAGE_KEY, themeId);
  } catch {
    // ignore
  }
}
