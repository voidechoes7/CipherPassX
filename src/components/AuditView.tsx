import React, { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Copy,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { vaultApi } from "../api/vaultApi";
import type { SecurityAuditReport } from "../types";

interface Props {
  onSelectEntry: (entryId: string) => void;
}

export const AuditView: React.FC<Props> = ({ onSelectEntry }) => {
  const [report, setReport] = useState<SecurityAuditReport | null>(null);
  const [loading, setLoading] = useState(true);

  const loadAudit = async () => {
    setLoading(true);
    try {
      const res = await vaultApi.runSecurityAudit();
      setReport(res);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAudit();
  }, []);

  if (loading || !report) {
    return (
      <div className="p-8 text-center text-sm text-slate-400">
        Running offline cryptographic &amp; password-hygiene audit...
      </div>
    );
  }

  const kdfPenalty = report.kdf_meets_safe_floor ? 0 : 25;
  const weakPenalty = Math.min(report.weak_passwords.length * 10, 40);
  const reusedPenalty = Math.min(report.reused_passwords.length * 8, 30);
  const expiredPenalty = Math.min(report.expired_entries.length * 5, 15);

  const scoreTone =
    report.overall_score >= 80
      ? { text: "text-emerald-300", bar: "bg-emerald-400", label: "Strong" }
      : report.overall_score >= 50
      ? { text: "text-amber-300", bar: "bg-amber-400", label: "Fair — Improvements Needed" }
      : { text: "text-rose-300", bar: "bg-rose-400", label: "Needs Attention" };

  return (
    <div className="p-4 sm:p-6 space-y-5 max-w-4xl mx-auto">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white">Offline Security &amp; Post-Quantum Audit</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Computed 100% locally in memory — zero external APIs or telemetry. Recycle Bin entries are excluded.
          </p>
        </div>
        <button
          type="button"
          onClick={loadAudit}
          className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-medium text-cyan-300 flex items-center gap-1.5 shrink-0"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Re-scan
        </button>
      </div>

      {/* Score & Crypto Posture */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="cyber-panel rounded-2xl p-5 flex flex-col justify-between space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div className="text-xs text-slate-400">Vault Health Score</div>
            <span className={`text-[10px] font-semibold ${scoreTone.text}`}>
              {scoreTone.label}
            </span>
          </div>
          <div className={`text-4xl font-bold font-mono ${scoreTone.text}`}>
            {report.overall_score}
            <span className="text-base text-slate-500">/100</span>
          </div>
          <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${scoreTone.bar}`}
              style={{ width: `${Math.max(4, report.overall_score)}%` }}
            />
          </div>
          <div className="space-y-1 text-[11px] font-mono text-slate-400 pt-1 border-t border-slate-800/80">
            <div className="flex justify-between">
              <span>Active entries</span>
              <span className="text-slate-200">{report.total_entries}</span>
            </div>
            {weakPenalty > 0 && (
              <div className="flex justify-between text-rose-300">
                <span>Weak ({report.weak_passwords.length})</span>
                <span>-{weakPenalty} pts</span>
              </div>
            )}
            {reusedPenalty > 0 && (
              <div className="flex justify-between text-amber-300">
                <span>Reused ({report.reused_passwords.length})</span>
                <span>-{reusedPenalty} pts</span>
              </div>
            )}
            {expiredPenalty > 0 && (
              <div className="flex justify-between text-violet-300">
                <span>Expired ({report.expired_entries.length})</span>
                <span>-{expiredPenalty} pts</span>
              </div>
            )}
            {kdfPenalty > 0 && (
              <div className="flex justify-between text-amber-300">
                <span>Weak KDF</span>
                <span>-{kdfPenalty} pts</span>
              </div>
            )}
            {weakPenalty === 0 && reusedPenalty === 0 && expiredPenalty === 0 && kdfPenalty === 0 && (
              <div className="text-emerald-300">Zero penalties detected!</div>
            )}
          </div>
        </div>

        <div className="cyber-panel rounded-2xl p-5 space-y-2">
          <div className="text-xs text-slate-400">KDBX 4 Cryptography</div>
          <div className="text-xs font-mono text-white">{report.cipher_summary}</div>
          <div className="text-xs font-mono text-violet-300">{report.kdf_summary}</div>
          <div className="flex items-center gap-1.5 text-xs pt-1">
            {report.kdf_meets_safe_floor ? (
              <>
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span className="text-emerald-300">KDF meets safe floor</span>
              </>
            ) : (
              <>
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span className="text-amber-300">KDF below recommended floor</span>
              </>
            )}
          </div>
        </div>

        <div className="cyber-panel rounded-2xl p-5 space-y-2">
          <div className="text-xs text-slate-400">Post-Quantum Readiness</div>
          <div className="flex items-center gap-2 mt-1">
            {report.post_quantum_ready ? (
              <ShieldCheck className="w-7 h-7 text-cyan-400" />
            ) : (
              <ShieldAlert className="w-7 h-7 text-amber-400" />
            )}
            <span className="text-sm font-semibold text-white">
              {report.post_quantum_ready ? "PQ-Hardened" : "Action Recommended"}
            </span>
          </div>
          <div className="text-[11px] text-slate-400">
            256-bit symmetric cipher + HMAC-SHA256 provides 128-bit post-quantum Grover security.
            {!report.post_quantum_ready && report.weak_passwords.length > 0
              ? ` Strengthen ${report.weak_passwords.length} weak password(s) to reach PQ-Hardened.`
              : ""}
          </div>
        </div>
      </div>

      {/* Findings */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="cyber-panel rounded-2xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-rose-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              Weak Passwords ({report.weak_passwords.length})
            </h3>
          </div>
          {report.weak_passwords.length === 0 ? (
            <p className="text-xs text-emerald-300">All passwords exceed 60 bits of entropy.</p>
          ) : (
            <div className="space-y-2">
              {report.weak_passwords.map((item) => (
                <button
                  key={item.entry_id}
                  type="button"
                  onClick={() => onSelectEntry(item.entry_id)}
                  className="w-full text-left rounded-xl bg-[#07090F] hover:bg-slate-900 border border-slate-800 px-3.5 py-2.5 transition"
                >
                  <div className="text-xs font-semibold text-white">{item.title}</div>
                  <div className="text-[11px] text-rose-300 font-mono mt-0.5">{item.detail}</div>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="cyber-panel rounded-2xl p-5 space-y-3">
          <h3 className="text-sm font-semibold text-amber-300 flex items-center gap-2">
            <Copy className="w-4 h-4" />
            Reused Passwords ({report.reused_passwords.length})
          </h3>
          {report.reused_passwords.length === 0 ? (
            <p className="text-xs text-emerald-300">No duplicate passwords detected.</p>
          ) : (
            <div className="space-y-2">
              {report.reused_passwords.map((item) => (
                <button
                  key={item.entry_id}
                  type="button"
                  onClick={() => onSelectEntry(item.entry_id)}
                  className="w-full text-left rounded-xl bg-[#07090F] hover:bg-slate-900 border border-slate-800 px-3.5 py-2.5 transition"
                >
                  <div className="text-xs font-semibold text-white">{item.title}</div>
                  <div className="text-[11px] text-amber-300 font-mono mt-0.5">{item.detail}</div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {report.expired_entries.length > 0 && (
        <div className="cyber-panel rounded-2xl p-5 space-y-3">
          <h3 className="text-sm font-semibold text-violet-300 flex items-center gap-2">
            <Clock className="w-4 h-4" />
            Expired Credentials ({report.expired_entries.length})
          </h3>
          <div className="space-y-2">
            {report.expired_entries.map((item) => (
              <button
                key={item.entry_id}
                type="button"
                onClick={() => onSelectEntry(item.entry_id)}
                className="w-full text-left rounded-xl bg-[#07090F] hover:bg-slate-900 border border-slate-800 px-3.5 py-2.5 transition"
              >
                <div className="text-xs font-semibold text-white">{item.title}</div>
                <div className="text-[11px] text-violet-300 font-mono mt-0.5">{item.detail}</div>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
