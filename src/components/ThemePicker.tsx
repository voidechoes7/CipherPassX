import React from "react";
import { Palette } from "lucide-react";
import { THEMES, type ThemeId } from "../themes";

interface Props {
  theme: ThemeId;
  onChange: (next: ThemeId) => void;
  compact?: boolean;
}

export const ThemePicker: React.FC<Props> = ({ theme, onChange, compact = false }) => {
  if (compact) {
    const idx = THEMES.findIndex((t) => t.id === theme);
    const current = THEMES[idx >= 0 ? idx : 0];
    const nextTheme = THEMES[(idx + 1) % THEMES.length];

    return (
      <button
        type="button"
        onClick={() => onChange(nextTheme.id)}
        title={`Theme: ${current.name} (tap to switch)`}
        className="px-2.5 py-1.5 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-slate-700/80 text-[11px] font-medium text-slate-200 flex items-center gap-1.5 shrink-0 transition"
      >
        <span
          className="w-2.5 h-2.5 rounded-full shrink-0"
          style={{
            background: `linear-gradient(135deg, ${current.swatchPrimary}, ${current.swatchSecondary})`,
          }}
        />
        <Palette className="w-3.5 h-3.5 text-slate-400" />
        <span className="hidden sm:inline whitespace-nowrap">{current.name}</span>
      </button>
    );
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
      {THEMES.map((t) => {
        const active = t.id === theme;
        return (
          <button
            key={t.id}
            type="button"
            onClick={() => onChange(t.id)}
            className={`text-left rounded-xl p-3 border transition flex items-center gap-3 ${
              active
                ? "bg-slate-900/90 border-cyan-400/60 cyber-glow"
                : "bg-[#07090F]/80 border-slate-800 hover:border-slate-700"
            }`}
          >
            <div
              className="w-8 h-8 rounded-lg shrink-0 border border-white/10"
              style={{
                background: `linear-gradient(135deg, ${t.swatchPrimary}, ${t.swatchSecondary})`,
              }}
            />
            <div className="min-w-0">
              <div className="text-xs font-semibold text-white truncate">{t.name}</div>
              <div className="text-[10px] text-slate-400 truncate">{t.subtitle}</div>
            </div>
          </button>
        );
      })}
    </div>
  );
};
