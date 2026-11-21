import React, { useEffect, useState } from "react";
import { Copy, ShieldCheck } from "lucide-react";
import { vaultApi } from "../api/vaultApi";
import type { TotpCode } from "../types";

interface Props {
  uriOrSecret: string;
  onCopy: (secret: string, label: string) => void;
  compact?: boolean;
}

export const TotpBadge: React.FC<Props> = ({ uriOrSecret, onCopy, compact = false }) => {
  const [totp, setTotp] = useState<TotpCode | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      try {
        const res = await vaultApi.getTotpCode(uriOrSecret);
        if (active) {
          setTotp(res);
          setErr(null);
        }
      } catch (e) {
        if (active) setErr(String(e));
      }
    };
    refresh();
    const timer = setInterval(refresh, 1000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [uriOrSecret]);

  if (err) {
    return (
      <div className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 rounded-lg px-3 py-2">
        Invalid TOTP secret/URI: {err}
      </div>
    );
  }

  if (!totp) return null;

  const progress = totp.remaining_seconds / totp.period;
  const radius = 14;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference * (1 - progress);
  const urgent = totp.remaining_seconds <= 5;
  const formattedCode =
    totp.code.length === 6
      ? `${totp.code.slice(0, 3)} ${totp.code.slice(3)}`
      : totp.code;

  return (
    <div
      className={`flex items-center justify-between gap-3 rounded-xl border ${
        urgent
          ? "bg-rose-500/10 border-rose-500/40"
          : "bg-cyan-500/5 border-cyan-500/25"
      } ${compact ? "px-3 py-2" : "px-4 py-3"}`}
    >
      <div className="flex items-center gap-3">
        <div className="relative w-9 h-9 flex items-center justify-center shrink-0">
          <svg className="w-9 h-9 -rotate-90" viewBox="0 0 36 36">
            <circle
              cx="18"
              cy="18"
              r={radius}
              fill="none"
              stroke="rgba(148,163,184,0.2)"
              strokeWidth="3"
            />
            <circle
              cx="18"
              cy="18"
              r={radius}
              fill="none"
              stroke={urgent ? "#f43f5e" : "#00f0ff"}
              strokeWidth="3"
              strokeDasharray={circumference}
              strokeDashoffset={dashOffset}
              strokeLinecap="round"
              className="transition-all duration-500"
            />
          </svg>
          <span className="absolute text-[10px] font-mono text-slate-300">
            {totp.remaining_seconds}
          </span>
        </div>

        <div>
          <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-slate-400">
            <ShieldCheck className="w-3 h-3 text-cyan-400" />
            <span>TOTP 2FA {totp.issuer ? `· ${totp.issuer}` : ""}</span>
          </div>
          <div
            className={`font-mono font-bold tracking-widest ${
              compact ? "text-lg" : "text-2xl"
            } ${urgent ? "text-rose-300" : "text-cyan-300"}`}
          >
            {formattedCode}
          </div>
        </div>
      </div>

      <button
        type="button"
        onClick={() => onCopy(totp.code, "TOTP code")}
        className="px-3 py-2 rounded-lg bg-slate-800/80 hover:bg-cyan-500/20 border border-slate-700 hover:border-cyan-400/40 text-cyan-300 text-xs font-medium flex items-center gap-1.5 transition"
      >
        <Copy className="w-3.5 h-3.5" />
        Copy
      </button>
    </div>
  );
};
