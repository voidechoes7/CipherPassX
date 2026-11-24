import React from "react";
import { Check, Layers, Moon, Palette, Sun } from "lucide-react";
import {
  THEMES,
  UI_STYLES,
  type ThemeId,
  type ThemeOption,
  type UiStyleId,
} from "../themes";

interface ThemeProps {
  theme: ThemeId;
  onChange: (next: ThemeId) => void;
  compact?: boolean;
}

const ThemeCard: React.FC<{
  option: ThemeOption;
  active: boolean;
  onSelect: () => void;
}> = ({ option, active, onSelect }) => (
  <button
    type="button"
    onClick={onSelect}
    className={`text-left rounded-xl p-3 border transition flex items-center gap-3 ${
      active
        ? "bg-cyan-500/10 border-cyan-400/50 cyber-glow"
        : "bg-[#07090F]/80 border-slate-800 hover:border-slate-700"
    }`}
  >
    <div
      className="w-9 h-9 rounded-lg shrink-0 border border-slate-600/40 relative overflow-hidden flex items-end justify-end p-1"
      style={{ backgroundColor: option.swatchBg }}
    >
      <span
        className="w-4 h-4 rounded-full shadow-sm border border-white/30"
        style={{
          background: `linear-gradient(135deg, ${option.swatchPrimary}, ${option.swatchSecondary})`,
        }}
      />
    </div>
    <div className="min-w-0 flex-1">
      <div className="flex items-center justify-between gap-1">
        <span className="text-xs font-semibold text-white truncate">{option.name}</span>
        {active && <Check className="w-3.5 h-3.5 cyber-accent-text shrink-0" />}
      </div>
      <div className="text-[10px] text-slate-400 truncate mt-0.5">{option.subtitle}</div>
    </div>
  </button>
);

export const ThemePicker: React.FC<ThemeProps> = ({ theme, onChange, compact = false }) => {
  if (compact) {
    const idx = THEMES.findIndex((t) => t.id === theme);
    const current = THEMES[idx >= 0 ? idx : 0];
    const nextTheme = THEMES[(idx + 1) % THEMES.length];

    return (
      <button
        type="button"
        onClick={() => onChange(nextTheme.id)}
        title={`Theme: ${current.name} (${current.mode}) — tap to cycle`}
        className="px-2.5 py-1.5 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-slate-700/80 text-[11px] font-medium text-slate-200 flex items-center gap-1.5 shrink-0 transition"
      >
        <span
          className="w-2.5 h-2.5 rounded-full shrink-0 border border-white/25"
          style={{
            background: `linear-gradient(135deg, ${current.swatchPrimary}, ${current.swatchSecondary})`,
          }}
        />
        {current.mode === "light" ? (
          <Sun className="w-3.5 h-3.5 text-amber-400" />
        ) : (
          <Palette className="w-3.5 h-3.5 text-slate-400" />
        )}
        <span className="hidden sm:inline whitespace-nowrap">{current.name}</span>
      </button>
    );
  }

  const lightThemes = THEMES.filter((t) => t.mode === "light");
  const darkThemes = THEMES.filter((t) => t.mode === "dark");

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
          <Sun className="w-3.5 h-3.5 text-amber-400" />
          Light Themes ({lightThemes.length})
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
          {lightThemes.map((t) => (
            <ThemeCard
              key={t.id}
              option={t}
              active={t.id === theme}
              onSelect={() => onChange(t.id)}
            />
          ))}
        </div>
      </div>

      <div className="space-y-2">
        <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
          <Moon className="w-3.5 h-3.5 cyber-accent-text" />
          Dark Themes ({darkThemes.length})
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
          {darkThemes.map((t) => (
            <ThemeCard
              key={t.id}
              option={t}
              active={t.id === theme}
              onSelect={() => onChange(t.id)}
            />
          ))}
        </div>
      </div>
    </div>
  );
};

interface UiStyleProps {
  uiStyle: UiStyleId;
  onChange: (next: UiStyleId) => void;
  compact?: boolean;
}

export const UiStylePicker: React.FC<UiStyleProps> = ({
  uiStyle,
  onChange,
  compact = false,
}) => {
  if (compact) {
    const idx = UI_STYLES.findIndex((s) => s.id === uiStyle);
    const current = UI_STYLES[idx >= 0 ? idx : 0];
    const nextStyle = UI_STYLES[(idx + 1) % UI_STYLES.length];

    return (
      <button
        type="button"
        onClick={() => onChange(nextStyle.id)}
        title={`GUI Style: ${current.name} — tap to switch`}
        className="px-2.5 py-1.5 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-slate-700/80 text-[11px] font-medium text-slate-200 flex items-center gap-1.5 shrink-0 transition"
      >
        <Layers className="w-3.5 h-3.5 cyber-accent-text shrink-0" />
        <span className="hidden md:inline whitespace-nowrap">{current.name}</span>
      </button>
    );
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
      {UI_STYLES.map((style) => {
        const active = style.id === uiStyle;
        return (
          <button
            key={style.id}
            type="button"
            onClick={() => onChange(style.id)}
            className={`text-left rounded-2xl p-3.5 border transition space-y-2 ${
              active
                ? "bg-cyan-500/10 border-cyan-400/50 cyber-glow"
                : "bg-[#07090F]/80 border-slate-800 hover:border-slate-700"
            }`}
          >
            {/* Visual mini wireframe preview */}
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-white">{style.name}</span>
                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-400/30">
                  {style.badge}
                </span>
              </div>
              {active && <Check className="w-4 h-4 cyber-accent-text shrink-0" />}
            </div>

            {/* Distinct visual miniature preview bar */}
            <div
              className={`h-8 w-full flex items-center justify-between px-2.5 border ${
                style.id === "material-you"
                  ? "rounded-full bg-slate-800/80 border-transparent shadow-md"
                  : style.id === "liquid-glass"
                  ? "rounded-2xl bg-cyan-500/10 border-white/25 backdrop-blur-md"
                  : style.id === "minimal-sliding"
                  ? "rounded-md bg-transparent border-slate-700"
                  : "rounded-lg bg-[#0D111A] border-cyan-400/35"
              }`}
            >
              <div className="flex items-center gap-1.5">
                <span
                  className={`h-2.5 w-8 ${
                    style.id === "material-you" ? "rounded-full" : "rounded-sm"
                  }`}
                  style={{ background: "var(--accent-primary)" }}
                />
                <span className="h-2 w-12 rounded-sm bg-slate-500/35" />
              </div>
              <span
                className={`h-4 w-10 ${
                  style.id === "material-you"
                    ? "rounded-full"
                    : style.id === "liquid-glass"
                    ? "rounded-xl"
                    : "rounded"
                }`}
                style={{
                  background:
                    "linear-gradient(135deg, var(--accent-primary), var(--accent-secondary))",
                }}
              />
            </div>

            <div className="text-[11px] font-medium text-slate-200 leading-snug">
              {style.tagline}
            </div>
            <div className="text-[10px] text-slate-400 leading-snug">{style.description}</div>
          </button>
        );
      })}
    </div>
  );
};
