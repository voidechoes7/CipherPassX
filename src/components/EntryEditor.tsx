import React, { useEffect, useMemo, useState } from "react";
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
  EntryType,
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

const RESERVED_KEYS_BY_TYPE: Record<EntryType, string[]> = {
  login: ["EntryType"],
  card: [
    "EntryType",
    "Cardholder",
    "Card Number",
    "Expiration",
    "CVV",
    "PIN",
    "IBAN / Account",
  ],
  totp: ["EntryType", "Recovery Codes"],
  dev: ["EntryType", "SSH Passphrase", "Private Key", "Public Key", "API Token"],
  note: ["EntryType"],
};

const ENTRY_TYPE_META: {
  id: EntryType;
  label: string;
  shortDesc: string;
  icon: React.FC<{ className?: string }>;
}[] = [
  {
    id: "login",
    label: "Login",
    shortDesc: "Website, username & password",
    icon: KeyRound,
  },
  {
    id: "card",
    label: "Bank / Card",
    shortDesc: "Card number, expiry, CVV, PIN & IBAN",
    icon: CreditCard,
  },
  {
    id: "totp",
    label: "2FA Token",
    shortDesc: "Offline RFC 6238 authenticator & recovery",
    icon: ShieldCheck,
  },
  {
    id: "dev",
    label: "SSH / API",
    shortDesc: "API tokens, SSH keys & passphrases",
    icon: Terminal,
  },
  {
    id: "note",
    label: "Secure Note",
    shortDesc: "Encrypted notes, seeds & documents",
    icon: FileText,
  },
];

function flattenGroups(node: GroupNode, depth = 0): { id: string; name: string; label: string }[] {
  const prefix = depth > 0 ? `${"— ".repeat(depth)}` : "";
  const list = [{ id: node.id, name: node.name, label: `${prefix}${node.name}` }];
  for (const sub of node.subgroups) {
    list.push(...flattenGroups(sub, depth + 1));
  }
  return list;
}

function getFieldValue(fields: CustomField[], key: string): string {
  return (
    fields.find((f) => f.key.toLowerCase() === key.toLowerCase())?.value ?? ""
  );
}

function detectEntryType(entry: EntryDetail | null, initialFocusTotp: boolean): EntryType {
  if (!entry) {
    return initialFocusTotp ? "totp" : "login";
  }

  const explicit = getFieldValue(entry.custom_fields, "EntryType").trim().toLowerCase();
  if (
    explicit === "login" ||
    explicit === "card" ||
    explicit === "totp" ||
    explicit === "dev" ||
    explicit === "note"
  ) {
    return explicit;
  }

  const hasKey = (k: string) =>
    entry.custom_fields.some((f) => f.key.toLowerCase() === k.toLowerCase());

  if (hasKey("Card Number") || hasKey("CVV") || hasKey("IBAN / Account")) {
    return "card";
  }
  if (
    hasKey("API Token") ||
    hasKey("SSH Passphrase") ||
    hasKey("Private Key") ||
    hasKey("Public Key")
  ) {
    return "dev";
  }
  if (entry.totp_uri && !entry.password) {
    return "totp";
  }
  if (
    (hasKey("Recovery Seed") || entry.notes.trim().length > 0) &&
    !entry.password &&
    !entry.username.trim() &&
    !entry.url.trim()
  ) {
    return "note";
  }
  return "login";
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
  const groupOptions = useMemo(() => flattenGroups(groups), [groups]);

  const [entryType, setEntryType] = useState<EntryType>(() =>
    detectEntryType(entry, initialFocusTotp)
  );
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
  const [showLoginTotp, setShowLoginTotp] = useState(Boolean(entry?.totp_uri));
  const [expires, setExpires] = useState(entry?.expires ?? false);
  const [expiryDate, setExpiryDate] = useState(
    entry?.expiry_time ? entry.expiry_time.slice(0, 10) : ""
  );

  // Exclusive structured fields — Bank / Card
  const [cardholder, setCardholder] = useState("");
  const [cardNumber, setCardNumber] = useState("");
  const [cardExpiration, setCardExpiration] = useState("");
  const [cardCvv, setCardCvv] = useState("");
  const [cardPin, setCardPin] = useState("");
  const [cardIban, setCardIban] = useState("");

  // Exclusive structured fields — 2FA Recovery
  const [recoveryCodes, setRecoveryCodes] = useState("");

  // Exclusive structured fields — SSH / API
  const [sshPassphrase, setSshPassphrase] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [publicKey, setPublicKey] = useState("");

  // Any extra user-added custom fields not mapped above
  const [extraFields, setExtraFields] = useState<CustomField[]>([]);

  const [showPassword, setShowPassword] = useState(false);
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, boolean>>({});
  const [showGenerator, setShowGenerator] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [entropy, setEntropy] = useState<EntropyReport | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const detected = detectEntryType(entry, initialFocusTotp);
    const cfs = entry?.custom_fields ?? [];
    const reserved = new Set(
      RESERVED_KEYS_BY_TYPE[detected].map((k) => k.toLowerCase())
    );

    setEntryType(detected);
    setGroupId(entry?.group_id ?? defaultGroupId);
    setTitle(entry?.title ?? "");
    setUsername(entry?.username ?? "");

    // For legacy dev entries that stored token in custom field "API Token" instead of password
    const legacyApiToken = getFieldValue(cfs, "API Token");
    setPassword(
      entry?.password || (detected === "dev" ? legacyApiToken : "")
    );

    setUrl(entry?.url ?? "");
    setNotes(entry?.notes ?? "");
    setFavorite(entry?.favorite ?? false);
    setTagsText(
      (entry?.tags ?? []).filter((t) => t.toLowerCase() !== "favorites").join(", ")
    );
    setTotpUri(entry?.totp_uri ?? "");
    setShowLoginTotp(Boolean(entry?.totp_uri));
    setExpires(entry?.expires ?? false);
    setExpiryDate(entry?.expiry_time ? entry.expiry_time.slice(0, 10) : "");

    // Bank / Card fields
    setCardholder(getFieldValue(cfs, "Cardholder"));
    setCardNumber(getFieldValue(cfs, "Card Number"));
    setCardExpiration(getFieldValue(cfs, "Expiration"));
    setCardCvv(getFieldValue(cfs, "CVV"));
    setCardPin(getFieldValue(cfs, "PIN"));
    setCardIban(getFieldValue(cfs, "IBAN / Account"));

    // 2FA Recovery
    setRecoveryCodes(getFieldValue(cfs, "Recovery Codes"));

    // SSH / API
    setSshPassphrase(getFieldValue(cfs, "SSH Passphrase"));
    setPrivateKey(getFieldValue(cfs, "Private Key"));
    setPublicKey(getFieldValue(cfs, "Public Key"));

    setExtraFields(
      cfs.filter((f) => !reserved.has(f.key.toLowerCase()))
    );

    setShowPassword(false);
    setRevealedSecrets({});
    setShowGenerator(false);
    setShowHistory(false);
    setError(null);
  }, [entry, defaultGroupId, initialFocusTotp]);

  useEffect(() => {
    if (!password || (entryType !== "login" && entryType !== "dev")) {
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
  }, [password, entryType]);

  const toggleReveal = (key: string) => {
    setRevealedSecrets((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleSelectEntryType = (nextType: EntryType) => {
    setEntryType(nextType);
    setError(null);
    setShowGenerator(false);

    // For brand-new entries, auto-select the best matching folder & clean default tag
    if (!entry) {
      const findGroup = (keyword: string) =>
        groupOptions.find((g) => g.name.toLowerCase().includes(keyword))?.id;

      if (nextType === "login") {
        setGroupId(findGroup("general") ?? defaultGroupId);
        if (["finance", "2fa", "dev, ssh", "note"].includes(tagsText)) setTagsText("");
      } else if (nextType === "card") {
        setGroupId(findGroup("bank") ?? defaultGroupId);
        if (!tagsText || ["2fa", "dev, ssh", "note"].includes(tagsText)) setTagsText("finance");
      } else if (nextType === "totp") {
        setGroupId(findGroup("2fa") ?? defaultGroupId);
        if (!tagsText || ["finance", "dev, ssh", "note"].includes(tagsText)) setTagsText("2fa");
      } else if (nextType === "dev") {
        setGroupId(findGroup("dev") ?? defaultGroupId);
        if (!tagsText || ["finance", "2fa", "note"].includes(tagsText)) setTagsText("dev, ssh");
      } else if (nextType === "note") {
        setGroupId(findGroup("general") ?? defaultGroupId);
        if (!tagsText || ["finance", "2fa", "dev, ssh"].includes(tagsText)) setTagsText("note");
      }
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

      const assembledFields: CustomField[] = [
        { key: "EntryType", value: entryType, protected: false },
      ];

      if (entryType === "card") {
        if (cardholder.trim())
          assembledFields.push({ key: "Cardholder", value: cardholder.trim(), protected: false });
        if (cardNumber.trim())
          assembledFields.push({ key: "Card Number", value: cardNumber.trim(), protected: true });
        if (cardExpiration.trim())
          assembledFields.push({ key: "Expiration", value: cardExpiration.trim(), protected: false });
        if (cardCvv.trim())
          assembledFields.push({ key: "CVV", value: cardCvv.trim(), protected: true });
        if (cardPin.trim())
          assembledFields.push({ key: "PIN", value: cardPin.trim(), protected: true });
        if (cardIban.trim())
          assembledFields.push({ key: "IBAN / Account", value: cardIban.trim(), protected: true });
      } else if (entryType === "totp") {
        if (recoveryCodes.trim())
          assembledFields.push({
            key: "Recovery Codes",
            value: recoveryCodes.trim(),
            protected: true,
          });
      } else if (entryType === "dev") {
        if (sshPassphrase.trim())
          assembledFields.push({
            key: "SSH Passphrase",
            value: sshPassphrase.trim(),
            protected: true,
          });
        if (privateKey.trim())
          assembledFields.push({ key: "Private Key", value: privateKey.trim(), protected: true });
        if (publicKey.trim())
          assembledFields.push({ key: "Public Key", value: publicKey.trim(), protected: false });
      }

      for (const cf of extraFields) {
        if (cf.key.trim().length > 0) {
          assembledFields.push({
            key: cf.key.trim(),
            value: cf.value,
            protected: cf.protected,
          });
        }
      }

      // Only store standard fields that belong to the active entry type (clean, no stray data)
      const saveUsername =
        entryType === "login" || entryType === "totp" || entryType === "dev"
          ? username
          : entryType === "card"
          ? cardholder.trim()
          : "";
      const savePassword =
        entryType === "login" || entryType === "dev" ? password : "";
      const saveUrl =
        entryType === "login" || entryType === "card" || entryType === "dev" ? url : "";
      const saveTotp =
        entryType === "totp" || (entryType === "login" && showLoginTotp)
          ? totpUri.trim() || null
          : null;

      const req: EntryUpsertRequest = {
        id: entry?.id ?? null,
        group_id: groupId,
        title: title.trim(),
        username: saveUsername,
        password: savePassword,
        url: saveUrl,
        notes,
        favorite,
        tags,
        totp_uri: saveTotp,
        custom_fields: assembledFields,
        expires: entryType === "login" || entryType === "dev" ? expires : false,
        expiry_time:
          (entryType === "login" || entryType === "dev") && expires && expiryDate
            ? `${expiryDate}T23:59:59Z`
            : null,
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

  const activeMeta = ENTRY_TYPE_META.find((m) => m.id === entryType) ?? ENTRY_TYPE_META[0];

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
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-white truncate">
              {entry ? entry.title || "Edit Entry" : `New ${activeMeta.label}`}
            </h2>
            <div className="text-[10px] text-slate-400 truncate hidden sm:block">
              {activeMeta.shortDesc}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
          {entry && entry.history.length > 0 && (
            <button
              type="button"
              onClick={() => setShowHistory(!showHistory)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs flex items-center gap-1"
              title="Password History"
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

      {/* Scrollable Section-Exclusive Editor Body */}
      <div className="flex-1 overflow-y-auto p-3 sm:p-5 space-y-4">
        {error && (
          <div className="rounded-xl bg-rose-500/10 border border-rose-500/40 px-3.5 py-2.5 text-xs text-rose-200">
            {error}
          </div>
        )}

        {/* Entry Type Selector — Always clearly highlighted so user knows the exact active category */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between gap-2 px-0.5">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
              Entry Category
            </span>
            <span className="text-[10px] text-slate-400 truncate">
              {activeMeta.shortDesc}
            </span>
          </div>
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
            {ENTRY_TYPE_META.map((tpl) => {
              const Icon = tpl.icon;
              const isSelected = entryType === tpl.id;
              return (
                <button
                  key={tpl.id}
                  type="button"
                  onClick={() => handleSelectEntryType(tpl.id)}
                  className={`px-3 py-2 rounded-xl border text-xs font-semibold flex items-center gap-1.5 whitespace-nowrap shrink-0 transition ${
                    isSelected
                      ? "cyber-btn-primary border-transparent"
                      : "bg-[#0D111A] hover:bg-slate-800 border-slate-800 text-slate-300"
                  }`}
                >
                  <Icon className={`w-3.5 h-3.5 ${isSelected ? "" : "cyber-accent-text"}`} />
                  {tpl.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* ============================================================
            SECTION A: LOGIN (Account + Credentials + Optional 2FA)
           ============================================================ */}
        {entryType === "login" && (
          <div className="space-y-4 deck-animate">
            {totpUri.trim() && <TotpBadge uriOrSecret={totpUri} onCopy={onCopy} />}

            {/* Card 1: Account Identity */}
            <div className="cyber-panel rounded-2xl p-4 space-y-3.5">
              <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text flex items-center gap-1.5">
                <KeyRound className="w-3.5 h-3.5" />
                1 · Login Account Identity
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Service / Title *</label>
                  <input
                    type="text"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder="e.g., GitHub, Proton Mail, Netflix"
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
              <div>
                <label className="block text-xs text-slate-400 mb-1">Website / Login URL</label>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com/login"
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              </div>
            </div>

            {/* Card 2: Sign-In Credentials */}
            <div className="cyber-panel rounded-2xl p-4 space-y-3.5">
              <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text">
                2 · Sign-In Credentials (Encrypted)
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

            {/* Card 3: Optional 2FA / TOTP Attachment */}
            <div className="cyber-panel rounded-2xl p-4 space-y-2.5">
              <div className="flex items-center justify-between gap-2">
                <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  3 · Linked 2FA / TOTP (Optional)
                </div>
                <button
                  type="button"
                  onClick={() => setShowLoginTotp(!showLoginTotp)}
                  className="text-xs font-medium text-cyan-300 hover:opacity-80"
                >
                  {showLoginTotp ? "Hide" : "+ Attach 2FA"}
                </button>
              </div>
              {showLoginTotp && (
                <div className="space-y-1.5">
                  <input
                    type="text"
                    value={totpUri}
                    onChange={(e) => setTotpUri(e.target.value)}
                    placeholder="Base32 secret (JBSWY3DPEHPK3PXP) or otpauth://totp/... URI"
                    className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400"
                  />
                  <p className="text-[10px] text-slate-400">
                    Stored in KDBX 4 <code className="text-cyan-300">otp</code> field (KeePassXC &amp; KeePassDX compatible).
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ============================================================
            SECTION B: BANK / CARD (Exclusive Payment & Banking Fields)
           ============================================================ */}
        {entryType === "card" && (
          <div className="space-y-4 deck-animate">
            {/* Card 1: Card Identity */}
            <div className="cyber-panel rounded-2xl p-4 space-y-3.5">
              <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text flex items-center gap-1.5">
                <CreditCard className="w-3.5 h-3.5" />
                1 · Card &amp; Bank Identity
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">
                    Card Name / Bank *
                  </label>
                  <input
                    type="text"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder="e.g., BBVA Visa Platinum, Chase Debit"
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
            </div>

            {/* Card 2: Exclusive Payment Card Fields */}
            <div className="cyber-panel rounded-2xl p-4 space-y-3.5">
              <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text">
                2 · Card Details (ChaCha20 Protected)
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">Cardholder Name</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={cardholder}
                    onChange={(e) => setCardholder(e.target.value)}
                    placeholder="Full name as printed on card"
                    className="flex-1 min-w-0 rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-400"
                  />
                  {cardholder && (
                    <button
                      type="button"
                      onClick={() => onCopy(cardholder, "Cardholder")}
                      className="px-3 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 shrink-0"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">Card Number</label>
                <div className="flex gap-2">
                  <div className="relative flex-1 min-w-0">
                    <input
                      type={revealedSecrets["cardNumber"] ? "text" : "password"}
                      inputMode="numeric"
                      value={cardNumber}
                      onChange={(e) => setCardNumber(e.target.value)}
                      placeholder="4000 1234 5678 9010"
                      autoComplete="off"
                      className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 pl-3 pr-10 py-2 text-sm font-mono text-cyan-200 focus:outline-none focus:border-cyan-400"
                    />
                    <button
                      type="button"
                      onClick={() => toggleReveal("cardNumber")}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-300"
                    >
                      {revealedSecrets["cardNumber"] ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                  {cardNumber && (
                    <button
                      type="button"
                      onClick={() => onCopy(cardNumber.replace(/\s+/g, ""), "Card Number")}
                      className="px-3 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-400/30 text-cyan-300 shrink-0"
                      title="Copy card number"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Expiry (MM/YY)</label>
                  <input
                    type="text"
                    value={cardExpiration}
                    onChange={(e) => setCardExpiration(e.target.value)}
                    placeholder="08/29"
                    className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm font-mono text-white focus:outline-none focus:border-cyan-400"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">CVV / CVC</label>
                  <div className="flex gap-1.5">
                    <div className="relative flex-1 min-w-0">
                      <input
                        type={revealedSecrets["cardCvv"] ? "text" : "password"}
                        inputMode="numeric"
                        value={cardCvv}
                        onChange={(e) => setCardCvv(e.target.value)}
                        placeholder="•••"
                        autoComplete="off"
                        className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 pl-3 pr-9 py-2 text-sm font-mono text-cyan-200 focus:outline-none focus:border-cyan-400"
                      />
                      <button
                        type="button"
                        onClick={() => toggleReveal("cardCvv")}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-300"
                      >
                        {revealedSecrets["cardCvv"] ? (
                          <EyeOff className="w-3.5 h-3.5" />
                        ) : (
                          <Eye className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                    {cardCvv && (
                      <button
                        type="button"
                        onClick={() => onCopy(cardCvv, "CVV")}
                        className="px-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 shrink-0"
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">ATM / Card PIN</label>
                  <div className="flex gap-1.5">
                    <div className="relative flex-1 min-w-0">
                      <input
                        type={revealedSecrets["cardPin"] ? "text" : "password"}
                        inputMode="numeric"
                        value={cardPin}
                        onChange={(e) => setCardPin(e.target.value)}
                        placeholder="••••"
                        autoComplete="off"
                        className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 pl-3 pr-9 py-2 text-sm font-mono text-cyan-200 focus:outline-none focus:border-cyan-400"
                      />
                      <button
                        type="button"
                        onClick={() => toggleReveal("cardPin")}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-300"
                      >
                        {revealedSecrets["cardPin"] ? (
                          <EyeOff className="w-3.5 h-3.5" />
                        ) : (
                          <Eye className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                    {cardPin && (
                      <button
                        type="button"
                        onClick={() => onCopy(cardPin, "PIN")}
                        className="px-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 shrink-0"
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">
                    Account / IBAN / CLABE (Optional)
                  </label>
                  <div className="flex gap-1.5">
                    <input
                      type="text"
                      value={cardIban}
                      onChange={(e) => setCardIban(e.target.value)}
                      placeholder="Account number or CLABE..."
                      className="flex-1 min-w-0 rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm font-mono text-slate-200 focus:outline-none focus:border-cyan-400"
                    />
                    {cardIban && (
                      <button
                        type="button"
                        onClick={() => onCopy(cardIban, "Account / IBAN")}
                        className="px-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 shrink-0"
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">
                  Bank Portal Website (Optional)
                </label>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://bank.example.com"
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              </div>
            </div>
          </div>
        )}

        {/* ============================================================
            SECTION C: 2FA / TOTP TOKEN (Exclusive Authenticator Fields)
           ============================================================ */}
        {entryType === "totp" && (
          <div className="space-y-4 deck-animate">
            {totpUri.trim() && <TotpBadge uriOrSecret={totpUri} onCopy={onCopy} />}

            <div className="cyber-panel rounded-2xl p-4 space-y-3.5">
              <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5" />
                1 · 2FA Service Identity
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Service Name *</label>
                  <input
                    type="text"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder="e.g., GitHub 2FA, Binance, AWS"
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
              <div>
                <label className="block text-xs text-slate-400 mb-1">
                  Account Label / Email (Optional)
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="user@domain.com"
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm font-mono text-white focus:outline-none focus:border-cyan-400"
                />
              </div>
            </div>

            <div className="cyber-panel rounded-2xl p-4 space-y-3">
              <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text">
                2 · Offline RFC 6238 Secret Key
              </div>
              <input
                type="text"
                value={totpUri}
                autoFocus={initialFocusTotp}
                onChange={(e) => setTotpUri(e.target.value)}
                placeholder="Paste Base32 secret (JBSWY3DPEHPK3PXP) or otpauth://totp/... URI"
                className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400"
              />
              <p className="text-[10px] text-slate-400 leading-snug">
                Generates live 6-digit codes offline synced to your device clock. Saved inside the standard KDBX 4 <code className="text-cyan-300">otp</code> field.
              </p>
            </div>

            <div className="cyber-panel rounded-2xl p-4 space-y-2.5">
              <div className="flex items-center justify-between gap-2">
                <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text">
                  3 · Backup Recovery Codes (Protected)
                </div>
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => toggleReveal("recoveryCodes")}
                    className="text-[11px] text-slate-400 hover:text-cyan-300 flex items-center gap-1"
                  >
                    {revealedSecrets["recoveryCodes"] ? (
                      <>
                        <EyeOff className="w-3.5 h-3.5" /> Hide
                      </>
                    ) : (
                      <>
                        <Eye className="w-3.5 h-3.5" /> Reveal
                      </>
                    )}
                  </button>
                  {recoveryCodes && (
                    <button
                      type="button"
                      onClick={() => onCopy(recoveryCodes, "Recovery Codes")}
                      className="text-[11px] text-cyan-300 flex items-center gap-1"
                    >
                      <Copy className="w-3.5 h-3.5" /> Copy
                    </button>
                  )}
                </div>
              </div>
              {revealedSecrets["recoveryCodes"] || !recoveryCodes ? (
                <textarea
                  rows={3}
                  value={recoveryCodes}
                  onChange={(e) => setRecoveryCodes(e.target.value)}
                  placeholder="Paste one-time backup recovery codes here..."
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              ) : (
                <div className="rounded-xl bg-[#07090F] border border-slate-800 px-3 py-2.5 text-xs font-mono text-slate-400">
                  •••••••••••••••••••••••• (tap Reveal to view or edit)
                </div>
              )}
            </div>
          </div>
        )}

        {/* ============================================================
            SECTION D: SSH / API KEY (Exclusive Developer Secrets)
           ============================================================ */}
        {entryType === "dev" && (
          <div className="space-y-4 deck-animate">
            <div className="cyber-panel rounded-2xl p-4 space-y-3.5">
              <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5" />
                1 · Server / API Service Identity
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">
                    Key / Token Name *
                  </label>
                  <input
                    type="text"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder="e.g., Production VPS, OpenAI API, GitHub PAT"
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
              <div>
                <label className="block text-xs text-slate-400 mb-1">
                  Host / API Endpoint URL
                </label>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="ssh://root@10.0.0.1 or https://api.example.com"
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm font-mono text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              </div>
            </div>

            <div className="cyber-panel rounded-2xl p-4 space-y-3.5">
              <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text">
                2 · API Token &amp; SSH Key Material (Protected)
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">
                  Key ID / SSH Username
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="AKIA... / root / deploy"
                    className="flex-1 min-w-0 rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm font-mono text-white focus:outline-none focus:border-cyan-400"
                  />
                  {username && (
                    <button
                      type="button"
                      onClick={() => onCopy(username, "Key ID / User")}
                      className="px-3 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 shrink-0"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <label className="text-xs text-slate-400">API Token / Secret Key</label>
                  <button
                    type="button"
                    onClick={() => setShowGenerator(!showGenerator)}
                    className="text-xs font-semibold cyber-accent-text hover:opacity-80 flex items-center gap-1"
                  >
                    <Wand2 className="w-3.5 h-3.5" />
                    {showGenerator ? "Hide Generator" : "Generate Token"}
                  </button>
                </div>
                <div className="flex gap-2">
                  <div className="relative flex-1 min-w-0">
                    <input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="sk_live_... / ghp_..."
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
                      onClick={() => onCopy(password, "API Token")}
                      className="px-3 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-400/30 text-cyan-300 shrink-0"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  )}
                </div>

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

              <div>
                <label className="block text-xs text-slate-400 mb-1">
                  SSH Key Passphrase (Optional)
                </label>
                <div className="flex gap-2">
                  <div className="relative flex-1 min-w-0">
                    <input
                      type={revealedSecrets["sshPassphrase"] ? "text" : "password"}
                      value={sshPassphrase}
                      onChange={(e) => setSshPassphrase(e.target.value)}
                      placeholder="Passphrase protecting private key..."
                      autoComplete="off"
                      className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 pl-3 pr-10 py-2 text-sm font-mono text-cyan-200 focus:outline-none focus:border-cyan-400"
                    />
                    <button
                      type="button"
                      onClick={() => toggleReveal("sshPassphrase")}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-300"
                    >
                      {revealedSecrets["sshPassphrase"] ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                  {sshPassphrase && (
                    <button
                      type="button"
                      onClick={() => onCopy(sshPassphrase, "SSH Passphrase")}
                      className="px-3 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 shrink-0"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs text-slate-400">
                    Private Key / PEM (Optional)
                  </label>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => toggleReveal("privateKey")}
                      className="text-[11px] text-slate-400 hover:text-cyan-300"
                    >
                      {revealedSecrets["privateKey"] ? "Hide" : "Reveal"}
                    </button>
                    {privateKey && (
                      <button
                        type="button"
                        onClick={() => onCopy(privateKey, "Private Key")}
                        className="text-[11px] text-cyan-300"
                      >
                        Copy
                      </button>
                    )}
                  </div>
                </div>
                {revealedSecrets["privateKey"] || !privateKey ? (
                  <textarea
                    rows={3}
                    value={privateKey}
                    onChange={(e) => setPrivateKey(e.target.value)}
                    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                    className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400"
                  />
                ) : (
                  <div className="rounded-xl bg-[#07090F] border border-slate-800 px-3 py-2 text-xs font-mono text-slate-400">
                    [Encrypted Private Key stored — tap Reveal to view]
                  </div>
                )}
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">
                  Public Key / Fingerprint (Optional)
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={publicKey}
                    onChange={(e) => setPublicKey(e.target.value)}
                    placeholder="ssh-ed25519 AAAA... or SHA256:..."
                    className="flex-1 min-w-0 rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400"
                  />
                  {publicKey && (
                    <button
                      type="button"
                      onClick={() => onCopy(publicKey, "Public Key")}
                      className="px-3 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 shrink-0"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ============================================================
            SECTION E: SECURE NOTE / SEED (Exclusive Encrypted Note)
           ============================================================ */}
        {entryType === "note" && (
          <div className="space-y-4 deck-animate">
            <div className="cyber-panel rounded-2xl p-4 space-y-3.5">
              <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5" />
                1 · Secure Note Identity
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Note Title *</label>
                  <input
                    type="text"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder="e.g., Ledger Seed Phrase, Passport Info"
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
            </div>

            <div className="cyber-panel rounded-2xl p-4 space-y-2.5">
              <div className="flex items-center justify-between">
                <div className="text-[10px] font-bold uppercase tracking-wider cyber-accent-text">
                  2 · Encrypted Note Content
                </div>
                {notes && (
                  <button
                    type="button"
                    onClick={() => onCopy(notes, "Secure Note")}
                    className="text-xs text-cyan-300 flex items-center gap-1"
                  >
                    <Copy className="w-3.5 h-3.5" /> Copy
                  </button>
                )}
              </div>
              <textarea
                rows={7}
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Write your encrypted offline note, recovery instructions, or confidential details..."
                className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3.5 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-400 leading-relaxed"
              />
            </div>
          </div>
        )}

        {/* ============================================================
            SHARED FOOTER CARDS: Extra Custom Fields (Clean & On-Demand) + Tags/Notes
           ============================================================ */}
        <div className="cyber-panel rounded-2xl p-4 space-y-3">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
              Additional Protected Fields {extraFields.length > 0 ? `(${extraFields.length})` : "(Optional)"}
            </div>
            <button
              type="button"
              onClick={() =>
                setExtraFields([...extraFields, { key: "", value: "", protected: true }])
              }
              className="text-xs text-violet-300 hover:text-violet-200 flex items-center gap-1 font-medium"
            >
              <Plus className="w-3.5 h-3.5" /> Add Field
            </button>
          </div>

          {entryType === "note" && (
            <div className="flex flex-wrap gap-1.5">
              {["Recovery Seed", "Document ID", "Backup PIN", "Security Answer"].map((tpl) => (
                <button
                  key={tpl}
                  type="button"
                  onClick={() =>
                    setExtraFields([...extraFields, { key: tpl, value: "", protected: true }])
                  }
                  className="text-[10px] font-mono px-2.5 py-1 rounded-lg bg-[#07090F] hover:bg-slate-800 border border-slate-700/80 text-slate-300 hover:text-cyan-300 transition"
                >
                  + {tpl}
                </button>
              ))}
            </div>
          )}

          {extraFields.map((cf, idx) => (
            <div key={idx} className="flex flex-col sm:flex-row gap-2">
              <input
                type="text"
                value={cf.key}
                onChange={(e) => {
                  const next = [...extraFields];
                  next[idx] = { ...cf, key: e.target.value };
                  setExtraFields(next);
                }}
                placeholder="Field name"
                className="sm:w-40 rounded-lg bg-[#07090F] border border-slate-700 px-3 py-1.5 text-xs text-white"
              />
              <div className="flex flex-1 gap-1.5 min-w-0">
                <input
                  type={cf.protected && !revealedSecrets[`cf_${idx}`] ? "password" : "text"}
                  value={cf.value}
                  onChange={(e) => {
                    const next = [...extraFields];
                    next[idx] = { ...cf, value: e.target.value };
                    setExtraFields(next);
                  }}
                  placeholder="Value"
                  className="flex-1 min-w-0 rounded-lg bg-[#07090F] border border-slate-700 px-3 py-1.5 text-xs font-mono text-slate-200"
                />
                {cf.protected && (
                  <button
                    type="button"
                    onClick={() => toggleReveal(`cf_${idx}`)}
                    className="p-2 rounded-lg bg-slate-800 text-slate-400 hover:text-cyan-300 shrink-0"
                    title="Reveal/hide"
                  >
                    {revealedSecrets[`cf_${idx}`] ? (
                      <EyeOff className="w-3.5 h-3.5" />
                    ) : (
                      <Eye className="w-3.5 h-3.5" />
                    )}
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => {
                    const next = [...extraFields];
                    next[idx] = { ...cf, protected: !cf.protected };
                    setExtraFields(next);
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
                  onClick={() => setExtraFields(extraFields.filter((_, i) => i !== idx))}
                  className="p-2 rounded-lg bg-rose-500/10 text-rose-300 hover:bg-rose-500/20 shrink-0"
                  title="Remove field"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Tags, Optional Expiration (for Login/Dev) & Notes (when not Note type) */}
        <div className="cyber-panel rounded-2xl p-4 space-y-3">
          <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
            Organization {entryType !== "note" ? "& Notes" : ""}
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1 flex items-center gap-1">
              <Tag className="w-3 h-3" /> Tags (comma separated)
            </label>
            <input
              type="text"
              value={tagsText}
              onChange={(e) => setTagsText(e.target.value)}
              placeholder="personal, work, critical"
              className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-400"
            />
          </div>

          {(entryType === "login" || entryType === "dev") && (
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={expires}
                  onChange={(e) => setExpires(e.target.checked)}
                  className="accent-cyan-400"
                />
                Set Expiration Reminder
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
          )}

          {entryType !== "note" && (
            <div>
              <label className="block text-xs text-slate-400 mb-1">Notes (Optional)</label>
              <textarea
                rows={3}
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Additional encrypted notes..."
                className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-400"
              />
            </div>
          )}
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
