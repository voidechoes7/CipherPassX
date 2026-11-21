import React, { useCallback, useEffect, useState } from "react";
import { Check, Copy, Dices, KeyRound, RefreshCw } from "lucide-react";
import { vaultApi } from "../api/vaultApi";
import type { GeneratedSecret } from "../types";

interface Props {
  onCopy: (secret: string, label: string) => void;
  onApply?: (password: string) => void;
}

export const GeneratorPanel: React.FC<Props> = ({ onCopy, onApply }) => {
  const [mode, setMode] = useState<"password" | "passphrase">("password");

  // Password options
  const [length, setLength] = useState(24);
  const [lowercase, setLowercase] = useState(true);
  const [uppercase, setUppercase] = useState(true);
  const [digits, setDigits] = useState(true);
  const [symbols, setSymbols] = useState(true);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(false);

  // Diceware options
  const [wordCount, setWordCount] = useState(6);
  const [separator, setSeparator] = useState("-");
  const [capitalize, setCapitalize] = useState(true);
  const [includeNumber, setIncludeNumber] = useState(true);

  const [result, setResult] = useState<GeneratedSecret | null>(null);

  const generate = useCallback(async () => {
    try {
      const res =
        mode === "password"
          ? await vaultApi.generatePassword({
              length,
              lowercase,
              uppercase,
              digits,
              symbols,
              exclude_ambiguous: excludeAmbiguous,
            })
          : await vaultApi.generatePassphrase({
              word_count: wordCount,
              separator,
              capitalize,
              include_number: includeNumber,
            });
      setResult(res);
    } catch {
      // Ignore if running in browser preview without Tauri
    }
  }, [
    mode,
    length,
    lowercase,
    uppercase,
    digits,
    symbols,
    excludeAmbiguous,
    wordCount,
    separator,
    capitalize,
    includeNumber,
  ]);

  useEffect(() => {
    generate();
  }, [generate]);

  const scoreColor =
    (result?.entropy.score ?? 0) >= 85
      ? "bg-cyan-400"
      : (result?.entropy.score ?? 0) >= 60
      ? "bg-emerald-400"
      : (result?.entropy.score ?? 0) >= 35
      ? "bg-amber-400"
      : "bg-rose-500";

  return (
    <div className="space-y-5">
      {/* Mode Switch */}
      <div className="grid grid-cols-2 gap-2 p-1 rounded-xl bg-[#07090F] border border-slate-800">
        <button
          type="button"
          onClick={() => setMode("password")}
          className={`flex items-center justify-center gap-2 py-2 rounded-lg text-xs font-semibold transition ${
            mode === "password"
              ? "bg-cyan-500/15 text-cyan-300 border border-cyan-400/30"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <KeyRound className="w-3.5 h-3.5" />
          CSPRNG Password
        </button>
        <button
          type="button"
          onClick={() => setMode("passphrase")}
          className={`flex items-center justify-center gap-2 py-2 rounded-lg text-xs font-semibold transition ${
            mode === "passphrase"
              ? "bg-violet-500/15 text-violet-300 border border-violet-400/30"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <Dices className="w-3.5 h-3.5" />
          Diceware Passphrase
        </button>
      </div>

      {/* Generated Output */}
      <div className="rounded-xl bg-[#07090F] border border-cyan-500/30 p-4 space-y-3">
        <div className="font-mono text-base sm:text-lg text-cyan-200 break-all select-all leading-relaxed">
          {result?.value ?? "—"}
        </div>

        {/* Entropy Meter */}
        {result && (
          <div className="space-y-1.5">
            <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
              <div
                className={`h-full transition-all duration-300 ${scoreColor}`}
                style={{ width: `${result.entropy.score}%` }}
              />
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono">
              <span className="text-slate-300">{result.entropy.strength}</span>
              <span className="text-slate-400">
                {result.entropy.entropy_bits} bits ·{" "}
                <span className="text-cyan-300">
                  {result.entropy.post_quantum_bits} PQ-bits (Grover)
                </span>
              </span>
            </div>
          </div>
        )}

        <div className="flex flex-wrap gap-2 pt-1">
          <button
            type="button"
            onClick={generate}
            className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Regenerate
          </button>
          {result && (
            <button
              type="button"
              onClick={() => onCopy(result.value, "Generated secret")}
              className="px-3.5 py-2 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-400/30 text-cyan-300 text-xs font-medium flex items-center gap-1.5 transition"
            >
              <Copy className="w-3.5 h-3.5" />
              Copy (Auto-Clear)
            </button>
          )}
          {result && onApply && (
            <button
              type="button"
              onClick={() => onApply(result.value)}
              className="px-3.5 py-2 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-400/40 text-emerald-300 text-xs font-medium flex items-center gap-1.5 transition"
            >
              <Check className="w-3.5 h-3.5" />
              Use Password
            </button>
          )}
        </div>
      </div>

      {/* Controls */}
      {mode === "password" ? (
        <div className="space-y-4">
          <div>
            <div className="flex justify-between text-xs mb-1.5">
              <span className="text-slate-300">Length</span>
              <span className="font-mono text-cyan-300">{length} chars</span>
            </div>
            <input
              type="range"
              min={8}
              max={64}
              value={length}
              onChange={(e) => setLength(Number(e.target.value))}
              className="w-full accent-cyan-400"
            />
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs">
            {[
              { label: "a–z Lowercase", checked: lowercase, set: setLowercase },
              { label: "A–Z Uppercase", checked: uppercase, set: setUppercase },
              { label: "0–9 Digits", checked: digits, set: setDigits },
              { label: "!@# Symbols", checked: symbols, set: setSymbols },
              {
                label: "Exclude 0O1lI",
                checked: excludeAmbiguous,
                set: setExcludeAmbiguous,
              },
            ].map((item) => (
              <label
                key={item.label}
                className="flex items-center gap-2 rounded-lg bg-[#07090F] border border-slate-800 px-3 py-2 cursor-pointer hover:border-slate-700"
              >
                <input
                  type="checkbox"
                  checked={item.checked}
                  onChange={(e) => item.set(e.target.checked)}
                  className="accent-cyan-400"
                />
                <span className="text-slate-300">{item.label}</span>
              </label>
            ))}
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <div>
            <div className="flex justify-between text-xs mb-1.5">
              <span className="text-slate-300">Word Count</span>
              <span className="font-mono text-violet-300">{wordCount} words</span>
            </div>
            <input
              type="range"
              min={4}
              max={12}
              value={wordCount}
              onChange={(e) => setWordCount(Number(e.target.value))}
              className="w-full accent-violet-400"
            />
          </div>

          <div className="grid grid-cols-3 gap-3 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">Separator</label>
              <input
                type="text"
                maxLength={3}
                value={separator}
                onChange={(e) => setSeparator(e.target.value)}
                className="w-full rounded-lg bg-[#07090F] border border-slate-700 px-3 py-2 font-mono text-white"
              />
            </div>
            <label className="flex items-center gap-2 rounded-lg bg-[#07090F] border border-slate-800 px-3 py-2 cursor-pointer self-end">
              <input
                type="checkbox"
                checked={capitalize}
                onChange={(e) => setCapitalize(e.target.checked)}
                className="accent-violet-400"
              />
              <span className="text-slate-300">Capitalize</span>
            </label>
            <label className="flex items-center gap-2 rounded-lg bg-[#07090F] border border-slate-800 px-3 py-2 cursor-pointer self-end">
              <input
                type="checkbox"
                checked={includeNumber}
                onChange={(e) => setIncludeNumber(e.target.checked)}
                className="accent-violet-400"
              />
              <span className="text-slate-300">+3 Digits</span>
            </label>
          </div>
        </div>
      )}
    </div>
  );
};
