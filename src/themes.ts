export type ThemeMode = "light" | "dark";

export type ThemeId =
  | "porcelain-daylight"
  | "paper-sage"
  | "solar-sand"
  | "nordic-frost"
  | "obsidian-cyber"
  | "ciphergenx-gold"
  | "synthwave-crimson"
  | "matrix-stealth"
  | "arctic-titanium";

export interface ThemeOption {
  id: ThemeId;
  name: string;
  subtitle: string;
  mode: ThemeMode;
  swatchBg: string;
  swatchPrimary: string;
  swatchSecondary: string;
}

export const THEMES: ThemeOption[] = [
  // Light Themes (4)
  {
    id: "porcelain-daylight",
    name: "Porcelain Daylight",
    subtitle: "Crisp White + Cobalt Blue & Indigo",
    mode: "light",
    swatchBg: "#F4F7FB",
    swatchPrimary: "#2563EB",
    swatchSecondary: "#6366F1",
  },
  {
    id: "paper-sage",
    name: "Paper Sage",
    subtitle: "Soft Alabaster + Botanical Emerald",
    mode: "light",
    swatchBg: "#F3F7F4",
    swatchPrimary: "#059669",
    swatchSecondary: "#0D9488",
  },
  {
    id: "solar-sand",
    name: "Solar Sand",
    subtitle: "Warm Linen + Terracotta & Amber",
    mode: "light",
    swatchBg: "#FAF5EE",
    swatchPrimary: "#D97706",
    swatchSecondary: "#EA580C",
  },
  {
    id: "nordic-frost",
    name: "Nordic Frost",
    subtitle: "Ice Pearl + Glacier Sky & Iris",
    mode: "light",
    swatchBg: "#EFF4FA",
    swatchPrimary: "#0284C7",
    swatchSecondary: "#7C3AED",
  },
  // Dark Themes (5)
  {
    id: "obsidian-cyber",
    name: "Obsidian Cyber",
    subtitle: "Void + Neon Cyan / Violet",
    mode: "dark",
    swatchBg: "#07090F",
    swatchPrimary: "#00F0FF",
    swatchSecondary: "#8B5CF6",
  },
  {
    id: "ciphergenx-gold",
    name: "CipherGenX Carbon",
    subtitle: "Matte Carbon + Liquid Gold / Emerald",
    mode: "dark",
    swatchBg: "#08080A",
    swatchPrimary: "#F59E0B",
    swatchSecondary: "#10B981",
  },
  {
    id: "synthwave-crimson",
    name: "Neon Synthwave",
    subtitle: "Midnight + Hot Magenta / Cyan",
    mode: "dark",
    swatchBg: "#0A0510",
    swatchPrimary: "#FF2E93",
    swatchSecondary: "#00F0FF",
  },
  {
    id: "matrix-stealth",
    name: "Matrix Ghost",
    subtitle: "Pitch Black + Phosphor Emerald",
    mode: "dark",
    swatchBg: "#030805",
    swatchPrimary: "#00FF88",
    swatchSecondary: "#06B6D4",
  },
  {
    id: "arctic-titanium",
    name: "Arctic Titanium",
    subtitle: "Nordic Slate + Frost Blue / Indigo",
    mode: "dark",
    swatchBg: "#070D18",
    swatchPrimary: "#38BDF8",
    swatchSecondary: "#818CF8",
  },
];

export type UiStyleId =
  | "cyber-tactical"
  | "material-you"
  | "liquid-glass"
  | "minimal-sliding";

export interface UiStyleOption {
  id: UiStyleId;
  name: string;
  badge: string;
  tagline: string;
  description: string;
}

export const UI_STYLES: UiStyleOption[] = [
  {
    id: "cyber-tactical",
    name: "Cyber Tactical",
    badge: "PRECISION",
    tagline: "Crisp borders, geometric grid & luminous accents",
    description: "Compact high-density HUD cards with subtle accent glow and monospace telemetry.",
  },
  {
    id: "material-you",
    name: "Material 3",
    badge: "EXPRESSIVE",
    tagline: "Tonal elevated cards, soft shadows & pill controls",
    description: "Google Material You inspired rounded 24px surfaces, pill indicators, and gentle elevation.",
  },
  {
    id: "liquid-glass",
    name: "Liquid Glass",
    badge: "TRANSLUCENT",
    tagline: "Frosted glass panels, specular rims & floating dock",
    description: "Deep blur translucency over ambient gradients with luminous top-edge glass reflections.",
  },
  {
    id: "minimal-sliding",
    name: "Sliding Deck",
    badge: "EDITORIAL",
    tagline: "Ultra-clean hairline architecture & fluid slide motion",
    description: "Flat, distraction-free typography with crisp dividers and smooth sliding card transitions.",
  },
];

const THEME_STORAGE_KEY = "cipherpass_theme_v1";
const STYLE_STORAGE_KEY = "cipherpass_ui_style_v1";

export function getThemeOption(themeId: ThemeId): ThemeOption {
  return THEMES.find((t) => t.id === themeId) ?? THEMES[4];
}

export function loadSavedTheme(): ThemeId {
  try {
    const saved = localStorage.getItem(THEME_STORAGE_KEY) as ThemeId | null;
    if (saved && THEMES.some((t) => t.id === saved)) {
      return saved;
    }
  } catch {
    // ignore storage restrictions
  }
  return "obsidian-cyber";
}

export function applyTheme(themeId: ThemeId): void {
  const opt = getThemeOption(themeId);
  document.documentElement.setAttribute("data-theme", opt.id);
  document.documentElement.setAttribute("data-mode", opt.mode);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, opt.id);
  } catch {
    // ignore
  }
}

export function loadSavedUiStyle(): UiStyleId {
  try {
    const saved = localStorage.getItem(STYLE_STORAGE_KEY) as UiStyleId | null;
    if (saved && UI_STYLES.some((s) => s.id === saved)) {
      return saved;
    }
  } catch {
    // ignore
  }
  return "cyber-tactical";
}

export function applyUiStyle(styleId: UiStyleId): void {
  document.documentElement.setAttribute("data-ui-style", styleId);
  try {
    localStorage.setItem(STYLE_STORAGE_KEY, styleId);
  } catch {
    // ignore
  }
}
