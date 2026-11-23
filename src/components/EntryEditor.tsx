import React, { useEffect, useState } from "react";
import {
  ChevronLeft,
  Copy,
  CreditCard,
  Eye,
  EyeOff,
  FileText,
  History,
  KeyRound,
  Lock,
  Plus,
  Save,
  ShieldCheck,
  Star,
  Tag,
  Terminal,
  Trash2,
  Unlock,
  Wand2,
} from "lucide-react";
import { vaultApi } from "../api/vaultApi";
import type {
  CustomField,
  EntryDetail,
  EntryUpsertRequest,
  EntropyReport,
  GroupNode,
} from "../types";
import { GeneratorPanel } from "./GeneratorPanel";
import { TotpBadge } from "./TotpBadge";

interface Props {
  entry: EntryDetail | null;
  defaultGroupId: string;
  groups: GroupNode;
  initialFocusTotp?: boolean;
  onSaved: (saved: EntryDetail) => void;
  onDeleted: () => void;
  onCopy: (secret: string, label: string) => void;
  onBackMobile?: () => void;
}

function flattenGroups(node: GroupNode, depth = 0): { id: string; name: string; label: string }[] {
  const prefix = depth > 0 ? `${"— ".repeat(depth)}` : "";
  const list = [{ id: node.id, name: node.name, label: `${prefix}${node.name}` }];
  for (const sub of node.subgroups) {
    list.push(...flattenGroups(sub, depth + 1));
  }
  return list;
}

export const EntryEditor: React.FC<Props> = ({
  entry,
  defaultGroupId,
  groups,
  initialFocusTotp = false,
  onSaved,
  onDeleted,
  onCopy,
  onBackMobile,
}) => {
  const [groupId, setGroupId] = useState(entry?.group_id ?? defaultGroupId);
  const [title, setTitle] = useState(entry?.title ?? "");
  const [username, setUsername] = useState(entry?.username ?? "");
  const [password, setPassword] = useState(entry?.password ?? "");
  const [url, setUrl] = useState(entry?.url ?? "");
  const [notes, setNotes] = useState(entry?.notes ?? "");
  const [favorite, setFavorite] = useState(entry?.favorite ?? false);
  const [tagsText, setTagsText] = useState(
    (entry?.tags ?? []).filter((t) => t.toLowerCase() !== "favorites").join(", ")
  );
  const [totpUri, setTotpUri] = useState(entry?.totp_uri ?? "");
  const [customFields, setCustomFields] = useState<CustomField[]>(entry?.custom_fields ?? []);
  const [expires, setExpires] = useState(entry?.expires ?? false);
  const [expiryDate, setExpiryDate] = useState(
    entry?.expiry_time ? entry.expiry_time.slice(0, 10) : ""
  );

  const [showPassword, setShowPassword] = useState(false);
  const [revealedFields, setRevealedFields] = useState<Record<number, boolean>>({});
  const [showGenerator, setShowGenerator] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [entropy, setEntropy] = useState<EntropyReport | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const groupOptions = flattenGroups(groups);

  useEffect(() => {
    setGroupId(entry?.group_id ?? defaultGroupId);
    setTitle(entry?.title ?? "");
    setUsername(entry?.username ?? "");
    setPassword(entry?.password ?? "");
    setUrl(entry?.url ?? "");
    setNotes(entry?.notes ?? "");
    setFavorite(entry?.favorite ?? false);
    setTagsText(
      (entry?.tags ?? []).filter((t) => t.toLowerCase() !== "favorites").join(", ")
    );
    setTotpUri(entry?.totp_uri ?? "");
    setCustomFields(entry?.custom_fields ?? []);
    setExpires(entry?.expires ?? false);
    setExpiryDate(entry?.expiry_time ? entry.expiry_time.slice(0, 10) : "");
    setShowPassword(false);
    setRevealedFields({});
    setShowGenerator(false);
    setShowHistory(false);
    setError(null);
  }, [entry, defaultGroupId]);

  useEffect(() => {
    if (!password) {
      setEntropy(null);
      return;
    }
    let active = true;
    vaultApi
      .evaluatePassword(password)
      .then((res) => {
        if (active) setEntropy(res);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [password]);

  const applyTemplate = (kind: "login" | "totp" | "bank" | "dev" | "note") => {
    const findGroup = (keyword: string) =>
      groupOptions.find((g) => g.name.toLowerCase().includes(keyword))?.id;

    if (kind === "login") {
      setGroupId(findGroup("general") ?? defaultGroupId);
      setCustomFields([]);
    } else if (kind === "totp") {
      setGroupId(findGroup("2fa") ?? defaultGroupId);
      setTagsText("2fa");
    } else if (kind === "bank") {
      setGroupId(findGroup("bank") ?? defaultGroupId);
      setTagsText("finance");
      setCustomFields([
        { key: "Card Number", value: "", protected: true },
        { key: "Expiration", value: "", protected: false },
        { key: "CVV", value: "", protected: true },
        { key: "PIN", value: "", protected: true },
      ]);
    } else if (kind === "dev") {
      setGroupId(findGroup("dev") ?? defaultGroupId);
      setTagsText("dev, ssh");
      setCustomFields([
        { key: "API Token", value: "", protected: true },
        { key: "SSH Passphrase", value: "", protected: true },
      ]);
    } else if (kind === "note") {
      setGroupId(findGroup("general") ?? defaultGroupId);
      setTagsText("note");
      setCustomFields([{ key: "Recovery Seed", value: "", protected: true }]);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) {
      setError("Title is required.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const tags = tagsText
        .split(/[,;]/)
        .map((t) => t.trim())
        .filter(Boolean);
      const req: EntryUpsertRequest = {
        id: entry?.id ?? null,
        group_id: groupId,
        title: title.trim(),
        username,
        password,
        url,
        notes,
        favorite,
        tags,
        totp_uri: totpUri.trim() || null,
        custom_fields: customFields.filter((cf) => cf.key.trim().length > 0),
        expires,
        expiry_time: expires && expiryDate ? `${expiryDate}T23:59:59Z` : null,
      };
      const saved = await vaultApi.upsertEntry(req);
      onSaved(saved);
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!entry) return;
    try {
      await vaultApi.deleteEntry(entry.id);
      onDeleted();
    } catch (err) {
      setError(String(err));
    }
  };

  const entropyBarColor =
    (entropy?.score ?? 0) >= 85
      ? "bg-cyan-400"
      : (entropy?.score ?? 0) >= 60
      ? "bg-emerald-400"
      : (entropy?.score ?? 0) >= 35
      ? "bg-amber-400"
      : "bg-rose-500";

  return (
    <form onSubmit={handleSave} className="h-full flex flex-col overflow-hidden">
      {/* Sticky Top Action Bar */}
      <div className="flex items-center justify-between gap-2 px-3 sm:px-4 py-2.5 border-b border-slate-800/80 bg-[#0D111A]/95 shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          {onBackMobile && (
            <button
              type="button"
              onClick={onBackMobile}
              className="lg:hidden p-1.5 rounded-lg bg-slate-800 text-slate-200 shrink-0"
              aria-label="Back to list"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
          )}
          <button
            type="button"
            onClick={() => setFavorite(!favorite)}
            className={`p-1.5 rounded-lg border shrink-0 transition ${
              favorite
                ? "bg-amber-500/15 border-amber-400/40 text-amber-300"
                : "bg-slate-900 border-slate-800 text-slate-500 hover:text-slate-300"
            }`}
            title="Toggle Favorite"
          >
            <Star className={`w-4 h-4 ${favorite ? "fill-amber-300" : ""}`} />
          </button>
          <h2 className="text-sm font-semibold text-white truncate">
            {entry ? entry.title || "Edit Entry" : "New Vault Entry"}
          </h2>
        </div>

        <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
          {entry && entry.history.length > 0 && (
            <button
              type="button"
              onClick={() => setShowHistory(!showHistory)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs flex items-center gap-1"
            >
              <History className="w-3.5 h-3.5 text-violet-400" />
              <span>{entry.history.length}</span>
            </button>
          )}
          {entry && (
            <button
              type="button"
              onClick={handleDelete}
              className="p-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-300"
              title="Delete Entry"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          )}
          <button
            type="submit"
            disabled={saving}
            className="px-3.5 py-1.5 rounded-lg cyber-btn-primary font-bold text-xs flex items-center gap-1.5 transition"
          >
            <Save className="w-3.5 h-3.5" />
            {saving ? "Saving..." : "Save"}
          </button>
        </div>
      </div>

      {/* Scrollable Structured Cards Body */}
      <div className="flex-1 overflow-y-auto p-3 sm:p-5 space-y-4">
        {error && (
          <div className="rounded-xl bg-rose-500/10 border border-rose-500/40 px-3.5 py-2.5 text-xs text-rose-200">
            {error}
          </div>
        )}

        {/* Quick Templates Bar when creating a new entry */}
        {!entry && (
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
            {[
              { id: "login" as const, icon: KeyRound, label: "Login" },
              { id: "totp" as const, icon: ShieldCheck, label: "2FA Token" },
              { id: "bank" as const, icon: CreditCard, label: "Bank / Card" },
              { id: "dev" as const, icon: Terminal, label: "SSH / API" },
              { id: "note" as const, icon: FileText, label: "Recovery / Note" },
            ].map((tpl) => {
              const Icon = tpl.icon;
              return (
                <button
                  key={tpl.id}
                  type="button"
                  onClick={() => applyTemplate(tpl.id)}
                  className="px-2.5 py-1.5 rounded-lg bg-[#0D111A] hover:bg-slate-800 border border-slate-800 hover:border-cyan-400/40 text-[11px] font-medium text-slate-300 hover:text-cyan-200 flex items-center gap-1.5 whitespace-nowrap shrink-0 transition"
                >
                  <Icon className="w-3.5 h-3.5 text-cyan-400" />
                  {tpl.label}
                </button>
              );
            })}
          </div>
        )}

        {/* Live TOTP Preview (Always pinned at top if present) */}
        {totpUri.trim() && <TotpBadge uriOrSecret={totpUri} onCopy={onCopy} />}

        {/* Card 1: Identity & Folder */}
        <div className="cyber-panel rounded-2xl p-4 space-y-3.5">
          <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text">
            1 · Identity &amp; Folder
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Title *</label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g., GitHub, Proton, Bank"
                className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-400"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Folder / Group</label>
              <select
                value={groupId}
                onChange={(e) => setGroupId(e.target.value)}
                className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-400"
              >
                {groupOptions.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Website / URL</label>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://..."
                className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-400"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1 flex items-center gap-1">
                <Tag className="w-3 h-3" /> Tags
              </label>
              <input
                type="text"
                value={tagsText}
                onChange={(e) => setTagsText(e.target.value)}
                placeholder="dev, finance, critical"
                className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-400"
              />
            </div>
          </div>
        </div>

        {/* Card 2: Credentials */}
        <div className="cyber-panel rounded-2xl p-4 space-y-3.5">
          <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text">
            2 · Login Credentials (ChaCha20 Protected)
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">Username / Email</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="user@domain.com"
                className="flex-1 min-w-0 rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm font-mono text-white focus:outline-none focus:border-cyan-400"
              />
              {username && (
                <button
                  type="button"
                  onClick={() => onCopy(username, "Username")}
                  className="px-3 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 shrink-0"
                  title="Copy username"
                >
                  <Copy className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <label className="text-xs text-slate-400">Password</label>
              <button
                type="button"
                onClick={() => setShowGenerator(!showGenerator)}
                className="text-xs font-semibold cyber-accent-text hover:opacity-80 flex items-center gap-1"
              >
                <Wand2 className="w-3.5 h-3.5" />
                {showGenerator ? "Hide Generator" : "Generate CSPRNG"}
              </button>
            </div>
            <div className="flex gap-2">
              <div className="relative flex-1 min-w-0">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter or generate password..."
                  autoComplete="off"
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 pl-3 pr-10 py-2 text-sm font-mono text-cyan-200 focus:outline-none focus:border-cyan-400"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-300"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {password && (
                <button
                  type="button"
                  onClick={() => onCopy(password, "Password")}
                  className="px-3 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-400/30 text-cyan-300 shrink-0"
                  title="Copy password (auto-clears)"
                >
                  <Copy className="w-4 h-4" />
                </button>
              )}
            </div>

            {entropy && (
              <div className="space-y-1">
                <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${entropyBarColor}`}
                    style={{ width: `${entropy.score}%` }}
                  />
                </div>
                <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                  <span>{entropy.strength}</span>
                  <span>
                    {entropy.entropy_bits}b ·{" "}
                    <span className="text-cyan-300">{entropy.post_quantum_bits}b PQ</span>
                  </span>
                </div>
              </div>
            )}

            {showGenerator && (
              <div className="rounded-xl bg-[#07090F] border cyber-accent-border p-3.5 mt-2">
                <GeneratorPanel
                  onCopy={onCopy}
                  onApply={(pw) => {
                    setPassword(pw);
                    setShowGenerator(false);
                  }}
                />
              </div>
            )}
          </div>
        </div>

        {/* Card 3: 2FA / TOTP Authenticator */}
        <div
          className={`cyber-panel rounded-2xl p-4 space-y-2.5 ${
            initialFocusTotp ? "border-cyan-400/50" : ""
          }`}
        >
          <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5" />
            3 · 2FA / TOTP Authenticator (Offline RFC 6238)
          </div>
          <input
            type="text"
            value={totpUri}
            autoFocus={initialFocusTotp}
            onChange={(e) => setTotpUri(e.target.value)}
            placeholder="Paste Base32 secret (JBSWY3DPEHPK3PXP) or otpauth://totp/... URI"
            className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400"
          />
          <p className="text-[10px] text-slate-500">
            Stored encrypted inside KDBX 4 (<code className="text-slate-400">otp</code> protected field — interoperable with KeePassXC &amp; KeePassDX).
          </p>
        </div>

        {/* Card 4: Custom Protected Fields */}
        <div className="cyber-panel rounded-2xl p-4 space-y-3">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text">
              4 · Custom Protected Fields
            </div>
            <button
              type="button"
              onClick={() =>
                setCustomFields([...customFields, { key: "", value: "", protected: true }])
              }
              className="text-xs text-violet-300 hover:text-violet-200 flex items-center gap-1 font-medium"
            >
              <Plus className="w-3.5 h-3.5" /> Add Field
            </button>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {["PIN", "Recovery Code", "Seed Phrase", "SSH Key"].map((tpl) => (
              <button
                key={tpl}
                type="button"
                onClick={() =>
                  setCustomFields([...customFields, { key: tpl, value: "", protected: true }])
                }
                className="text-[10px] font-mono px-2 py-1 rounded-md bg-[#07090F] hover:bg-slate-800 border border-slate-700/80 text-slate-300 hover:text-cyan-300 transition"
              >
                + {tpl}
              </button>
            ))}
          </div>

          {customFields.map((cf, idx) => (
            <div key={idx} className="flex flex-col sm:flex-row gap-2">
              <input
                type="text"
                value={cf.key}
                onChange={(e) => {
                  const next = [...customFields];
                  next[idx] = { ...cf, key: e.target.value };
                  setCustomFields(next);
                }}
                placeholder="Field name"
                className="sm:w-40 rounded-lg bg-[#07090F] border border-slate-700 px-3 py-1.5 text-xs text-white"
              />
              <div className="flex flex-1 gap-1.5 min-w-0">
                <input
                  type={cf.protected && !revealedFields[idx] ? "password" : "text"}
                  value={cf.value}
                  onChange={(e) => {
                    const next = [...customFields];
                    next[idx] = { ...cf, value: e.target.value };
                    setCustomFields(next);
                  }}
                  placeholder="Value"
                  className="flex-1 min-w-0 rounded-lg bg-[#07090F] border border-slate-700 px-3 py-1.5 text-xs font-mono text-slate-200"
                />
                {cf.protected && (
                  <button
                    type="button"
                    onClick={() =>
                      setRevealedFields({ ...revealedFields, [idx]: !revealedFields[idx] })
                    }
                    className="p-2 rounded-lg bg-slate-800 text-slate-400 hover:text-cyan-300 shrink-0"
                    title="Reveal/hide"
                  >
                    {revealedFields[idx] ? (
                      <EyeOff className="w-3.5 h-3.5" />
                    ) : (
                      <Eye className="w-3.5 h-3.5" />
                    )}
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => {
                    const next = [...customFields];
                    next[idx] = { ...cf, protected: !cf.protected };
                    setCustomFields(next);
                  }}
                  className={`p-2 rounded-lg border shrink-0 ${
                    cf.protected
                      ? "bg-cyan-500/15 border-cyan-400/40 text-cyan-300"
                      : "bg-slate-800 border-slate-700 text-slate-400"
                  }`}
                  title={cf.protected ? "ChaCha20 Protected" : "Unprotected"}
                >
                  {cf.protected ? <Lock className="w-3.5 h-3.5" /> : <Unlock className="w-3.5 h-3.5" />}
                </button>
                <button
                  type="button"
                  onClick={() => onCopy(cf.value, cf.key || "Custom field")}
                  className="p-2 rounded-lg bg-slate-800 text-slate-300 hover:text-cyan-300 shrink-0"
                  title="Copy value"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
                <button
                  type="button"
                  onClick={() => setCustomFields(customFields.filter((_, i) => i !== idx))}
                  className="p-2 rounded-lg bg-rose-500/10 text-rose-300 hover:bg-rose-500/20 shrink-0"
                  title="Remove field"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Card 5: Notes & Expiration */}
        <div className="cyber-panel rounded-2xl p-4 space-y-3">
          <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text">
            5 · Notes &amp; Expiration
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={expires}
                onChange={(e) => setExpires(e.target.checked)}
                className="accent-cyan-400"
              />
              Set Expiration Date
            </label>
            {expires && (
              <input
                type="date"
                value={expiryDate}
                onChange={(e) => setExpiryDate(e.target.value)}
                className="rounded-lg bg-[#07090F] border border-slate-700 px-3 py-1 text-xs font-mono text-white"
              />
            )}
          </div>
          <textarea
            rows={3}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Secure offline notes..."
            className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-400"
          />
        </div>

        {/* Password History */}
        {showHistory && entry && entry.history.length > 0 && (
          <div className="rounded-2xl bg-[#07090F] border border-violet-500/30 p-4 space-y-3">
            <div className="text-xs font-semibold text-violet-300 uppercase tracking-wider">
              Password History ({entry.history.length})
            </div>
            <div className="space-y-2">
              {[...entry.history].reverse().map((h) => (
                <div
                  key={h.index}
                  className="flex items-center justify-between gap-2 rounded-lg bg-[#0D111A] border border-slate-800 px-3 py-2 text-xs"
                >
                  <div className="min-w-0">
                    <div className="text-slate-400 font-mono text-[10px]">
                      {new Date(h.modified_at).toLocaleString()}
                    </div>
                    <div className="font-mono text-slate-200 truncate">
                      {h.password ? "••••••••••••" : "(empty)"}
                    </div>
                  </div>
                  <div className="flex gap-1.5 shrink-0">
                    <button
                      type="button"
                      onClick={() => onCopy(h.password, "Historical password")}
                      className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200"
                    >
                      Copy
                    </button>
                    <button
                      type="button"
                      onClick={() => setPassword(h.password)}
                      className="px-2 py-1 rounded bg-violet-500/20 hover:bg-violet-500/30 text-violet-200"
                    >
                      Restore
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </form>
  );
};
