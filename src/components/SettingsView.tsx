import React, { useEffect, useState } from "react";
import {
  Atom,
  CheckCircle2,
  Copy,
  Database,
  Download,
  Eye,
  EyeOff,
  FileKey2,
  Fingerprint,
  FolderInput,
  Info,
  KeyRound,
  Lock,
  Palette,
  Play,
  Save,
  Shield,
  ShieldCheck,
  Unlock,
  Wand2,
} from "lucide-react";
import {
  isMobilePlatform,
  pickOpenKeyfile,
  pickOpenPqFile,
  pickSaveKdbxFile,
  pickSaveKeyfile,
  pickSavePqFile,
  vaultApi,
} from "../api/vaultApi";
import type { ThemeId, UiStyleId } from "../themes";
import type {
  CipherAlgorithm,
  EntropyReport,
  KdfAlgorithm,
  MlKem1024Keypair,
  PqSelfTestResult,
  VaultStatus,
} from "../types";
import { FolderPickerModal } from "./FolderPickerModal";
import { GeneratorPanel } from "./GeneratorPanel";
import { ThemePicker, UiStylePicker } from "./ThemePicker";

interface Props {
  status: VaultStatus;
  theme: ThemeId;
  uiStyle: UiStyleId;
  onThemeChange: (t: ThemeId) => void;
  onUiStyleChange: (s: UiStyleId) => void;
  onStatusUpdated: (status: VaultStatus) => void;
  onCopy: (secret: string, label: string) => void;
}

type SettingsSection = "vault" | "crypto" | "appearance";

export const SettingsView: React.FC<Props> = ({
  status,
  theme,
  uiStyle,
  onThemeChange,
  onUiStyleChange,
  onStatusUpdated,
  onCopy,
}) => {
  const [section, setSection] = useState<SettingsSection>("vault");

  // Vault Metadata & Crypto State
  const [vaultName, setVaultName] = useState(status.database_name ?? "CipherPass Vault");
  const [vaultDesc, setVaultDesc] = useState(status.database_description ?? "");
  const [cipher, setCipher] = useState<CipherAlgorithm>(status.cipher ?? "ChaCha20");
  const [kdfAlg, setKdfAlg] = useState<KdfAlgorithm>(status.kdf?.algorithm ?? "Argon2id");
  const [memoryMib, setMemoryMib] = useState(status.kdf?.memory_mib ?? 128);
  const [iterations, setIterations] = useState(status.kdf?.iterations ?? 4);
  const [parallelism, setParallelism] = useState(status.kdf?.parallelism ?? 4);
  const [autoLock, setAutoLock] = useState(status.auto_lock_seconds);
  const [clipClear, setClipClear] = useState(status.clipboard_clear_seconds);

  // Master Password & Keyfile Rotation State
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [showMasterPw, setShowMasterPw] = useState(false);
  const [showMasterGen, setShowMasterGen] = useState(false);
  const [newPwEntropy, setNewPwEntropy] = useState<EntropyReport | null>(null);
  const [keyfileAction, setKeyfileAction] = useState<"keep" | "set" | "remove">("keep");
  const [newKeyfilePath, setNewKeyfilePath] = useState("");
  const [rotatingCreds, setRotatingCreds] = useState(false);

  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // NIST FIPS 203 ML-KEM-1024 Post-Quantum Armor state
  const [pqKeypair, setPqKeypair] = useState<MlKem1024Keypair | null>(null);
  const [pqPubKey, setPqPubKey] = useState("");
  const [pqSecKey, setPqSecKey] = useState("");
  const [pqSelfTest, setPqSelfTest] = useState<PqSelfTestResult | null>(null);
  const [runningSelfTest, setRunningSelfTest] = useState(false);
  const [sealingPq, setSealingPq] = useState(false);

  // Biometric & Folder Modal states
  const [bioEnabled, setBioEnabled] = useState(false);
  const [folderModalMode, setFolderModalMode] = useState<
    null | "move" | "backup" | "pq-seal"
  >(null);

  useEffect(() => {
    setVaultName(status.database_name ?? "CipherPass Vault");
    setVaultDesc(status.database_description ?? "");
    if (status.cipher) setCipher(status.cipher);
    if (status.kdf) {
      setKdfAlg(status.kdf.algorithm);
      setMemoryMib(status.kdf.memory_mib);
      setIterations(status.kdf.iterations);
      setParallelism(status.kdf.parallelism);
    }
    setAutoLock(status.auto_lock_seconds);
    setClipClear(status.clipboard_clear_seconds);
  }, [status]);

  useEffect(() => {
    if (!status.path) return;
    vaultApi
      .hasBiometricSlot(status.path)
      .then(setBioEnabled)
      .catch(() => setBioEnabled(false));
  }, [status.path]);

  useEffect(() => {
    if (!newPassword) {
      setNewPwEntropy(null);
      return;
    }
    let active = true;
    vaultApi
      .evaluatePassword(newPassword)
      .then((res) => {
        if (active) setNewPwEntropy(res);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [newPassword]);

  const handleSaveMetadata = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vaultName.trim()) {
      setError("Vault name cannot be empty.");
      return;
    }
    setSaving(true);
    setMessage(null);
    setError(null);
    try {
      const updated = await vaultApi.updateSecuritySettings({
        database_name: vaultName.trim(),
        database_description: vaultDesc.trim(),
      });
      onStatusUpdated(updated);
      setMessage("Vault name and description updated & re-encrypted atomically.");
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  };

  const handleSaveCrypto = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setMessage(null);
    setError(null);
    try {
      const updated = await vaultApi.updateSecuritySettings({
        cipher,
        kdf: {
          algorithm: kdfAlg,
          memory_mib: memoryMib,
          iterations,
          parallelism,
          version: 0x13,
        },
        auto_lock_seconds: autoLock,
        clipboard_clear_seconds: clipClear,
      });
      onStatusUpdated(updated);
      setMessage(
        `Vault re-encrypted atomically with ${cipher} + ${kdfAlg} (${memoryMib} MiB / ${iterations} rounds).`
      );
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  };

  const handleChangeMasterCredentials = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage(null);
    setError(null);

    if (status.has_master_password && !currentPassword) {
      setError("Enter your current Master Password to verify this change.");
      return;
    }
    if (newPassword !== confirmNewPassword) {
      setError("New Master Passwords do not match.");
      return;
    }
    const willHaveKeyfile =
      keyfileAction === "set"
        ? Boolean(newKeyfilePath.trim())
        : keyfileAction === "keep"
        ? status.has_keyfile
        : false;
    if (!newPassword && !willHaveKeyfile) {
      setError("Provide a new Master Password, attach a Keyfile, or both.");
      return;
    }
    if (keyfileAction === "set" && !newKeyfilePath.trim()) {
      setError("Select a Keyfile to attach.");
      return;
    }

    setRotatingCreds(true);
    try {
      const res = await vaultApi.changeMasterCredentials({
        current_password: currentPassword || null,
        new_password: newPassword || null,
        keyfile_action: keyfileAction,
        new_keyfile_path: keyfileAction === "set" ? newKeyfilePath.trim() : null,
      });
      onStatusUpdated(res.status);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmNewPassword("");
      setShowMasterGen(false);
      setKeyfileAction("keep");
      setNewKeyfilePath("");
      if (res.biometric_reset) {
        setBioEnabled(false);
        setMessage(
          "Master credentials updated & vault re-encrypted atomically! Previous Biometric keyslot was cleared — re-enable Biometrics below to bind your new key."
        );
      } else {
        setMessage(
          "Master credentials updated & KDBX 4 vault re-encrypted atomically!"
        );
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setRotatingCreds(false);
    }
  };

  const handleRunPqSelfTest = async () => {
    setRunningSelfTest(true);
    setError(null);
    try {
      const res = await vaultApi.runPqSelfTest();
      setPqSelfTest(res);
    } catch (err) {
      setError(String(err));
    } finally {
      setRunningSelfTest(false);
    }
  };

  const handleExportBackup = async () => {
    setMessage(null);
    setError(null);
    if (isMobilePlatform()) {
      setFolderModalMode("backup");
      return;
    }
    const dest = await pickSaveKdbxFile("CipherPass_Backup.kdbx");
    if (!dest) return;
    try {
      const saved = await vaultApi.exportVaultBackup(dest);
      setMessage(`Atomic KDBX 4 backup exported to ${saved}`);
    } catch (err) {
      setError(String(err));
    }
  };

  const handleSealPq = async () => {
    setError(null);
    setMessage(null);
    if (!pqPubKey.trim()) {
      setError("Generate or paste an ML-KEM-1024 Public Key first (Step 1).");
      return;
    }
    if (isMobilePlatform()) {
      setFolderModalMode("pq-seal");
      return;
    }
    const dest = await pickSavePqFile("CipherPass_QuantumBackup.kdbx.pq");
    if (!dest) return;
    setSealingPq(true);
    try {
      const saved = await vaultApi.exportPqArmoredVault(dest, pqPubKey.trim());
      setMessage(`Vault sealed with FIPS 203 ML-KEM-1024 to ${saved}`);
    } catch (err) {
      setError(String(err));
    } finally {
      setSealingPq(false);
    }
  };

  const handleGenerateKeyfile = async () => {
    setMessage(null);
    setError(null);
    const dest = await pickSaveKeyfile("CipherPass_Keyfile_v2.keyx");
    if (!dest) return;
    try {
      await vaultApi.generateKeyfileToPath(dest);
      setMessage(`Generated 256-bit Keyfile v2.0 XML at ${dest}`);
    } catch (err) {
      setError(String(err));
    }
  };

  const safeBaseName =
    (status.database_name || "CipherPass_Vault")
      .trim()
      .replace(/[^a-zA-Z0-9_-]+/g, "_") || "CipherPass_Vault";

  const entropyBarColor =
    (newPwEntropy?.score ?? 0) >= 85
      ? "bg-cyan-400"
      : (newPwEntropy?.score ?? 0) >= 60
      ? "bg-emerald-400"
      : (newPwEntropy?.score ?? 0) >= 35
      ? "bg-amber-400"
      : "bg-rose-500";

  return (
    <div className="p-3 sm:p-6 max-w-3xl mx-auto space-y-5">
      {/* Header + Segmented Section Switcher */}
      <div className="space-y-3">
        <div>
          <h2 className="text-lg sm:text-xl font-bold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 cyber-accent-text" />
            Vault Properties, Crypto &amp; GUI
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Inspect or modify this vault&apos;s Master Password, encryption protocol, post-quantum armor, and visual style.
          </p>
        </div>

        <div className="grid grid-cols-3 gap-1.5 p-1 rounded-xl bg-[#0D111A] border border-slate-800">
          {[
            { id: "vault" as const, label: "Vault & Key", icon: Database },
            { id: "crypto" as const, label: "Crypto & PQ", icon: Atom },
            { id: "appearance" as const, label: "Themes & GUI", icon: Palette },
          ].map((tab) => {
            const Icon = tab.icon;
            const active = section === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => {
                  setSection(tab.id);
                  setError(null);
                }}
                className={`py-2 px-2 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition whitespace-nowrap ${
                  active
                    ? "cyber-btn-primary"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Icon className="w-3.5 h-3.5 shrink-0" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {message && (
        <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/40 px-4 py-3 text-xs text-emerald-200 leading-relaxed">
          {message}
        </div>
      )}
      {error && (
        <div className="rounded-xl bg-rose-500/10 border border-rose-500/40 px-4 py-3 text-xs text-rose-200 leading-relaxed">
          {error}
        </div>
      )}

      {/* ============================================================
          TAB 1: VAULT PROPERTIES, MASTER PASSWORD & BACKUPS
         ============================================================ */}
      {section === "vault" && (
        <div className="space-y-5 deck-animate">
          {/* Active Vault Properties Summary Grid */}
          <div className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-3.5">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Database className="w-4 h-4 cyber-accent-text" />
                Open Vault Properties
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                {status.kdbx_version ?? "KDBX 4.0"} · UNLOCKED
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs">
              <div className="rounded-xl bg-[#07090F] border border-slate-800 p-2.5">
                <div className="text-[10px] text-slate-400">Outer Cipher</div>
                <div className="font-mono font-semibold text-cyan-300 mt-0.5 truncate">
                  {status.cipher ?? "ChaCha20"} (256b)
                </div>
              </div>
              <div className="rounded-xl bg-[#07090F] border border-slate-800 p-2.5">
                <div className="text-[10px] text-slate-400">Key Derivation</div>
                <div className="font-mono font-semibold text-white mt-0.5 truncate">
                  {status.kdf
                    ? `${status.kdf.algorithm} · ${status.kdf.memory_mib}M/${status.kdf.iterations}r`
                    : "Argon2id"}
                </div>
              </div>
              <div className="rounded-xl bg-[#07090F] border border-slate-800 p-2.5">
                <div className="text-[10px] text-slate-400">Inner Stream</div>
                <div className="font-mono font-semibold text-white mt-0.5 truncate">
                  {status.inner_cipher ?? "ChaCha20 (256-bit)"}
                </div>
              </div>
              <div className="rounded-xl bg-[#07090F] border border-slate-800 p-2.5">
                <div className="text-[10px] text-slate-400">Master Key</div>
                <div className="font-mono font-semibold text-emerald-300 mt-0.5 truncate">
                  {status.has_master_password ? "Password" : "No PW"}
                  {status.has_keyfile ? " + Keyfile" : ""}
                </div>
              </div>
              <div className="rounded-xl bg-[#07090F] border border-slate-800 p-2.5">
                <div className="text-[10px] text-slate-400">Entries Stored</div>
                <div className="font-mono font-semibold text-white mt-0.5">
                  {status.entry_count} records
                </div>
              </div>
              <div className="rounded-xl bg-[#07090F] border border-slate-800 p-2.5">
                <div className="text-[10px] text-slate-400">Post-Quantum</div>
                <div className="font-mono font-semibold text-violet-300 mt-0.5 truncate">
                  128b Grover + FIPS 203
                </div>
              </div>
            </div>

            {status.path && (
              <div className="rounded-xl bg-[#07090F] border border-slate-800 px-3 py-2 text-[10px] font-mono text-slate-400 break-all">
                File path: <span className="text-cyan-300">{status.path}</span>
              </div>
            )}
          </div>

          {/* Rename Vault & Description */}
          <form onSubmit={handleSaveMetadata} className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-3.5">
            <h3 className="text-sm font-bold text-white">Vault Name &amp; Description</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Vault Name</label>
                <input
                  type="text"
                  value={vaultName}
                  onChange={(e) => setVaultName(e.target.value)}
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-400"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Description</label>
                <input
                  type="text"
                  value={vaultDesc}
                  onChange={(e) => setVaultDesc(e.target.value)}
                  placeholder="Personal offline vault"
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              </div>
            </div>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 rounded-xl cyber-btn-primary text-xs font-bold flex items-center gap-1.5 transition"
            >
              <Save className="w-3.5 h-3.5" />
              {saving ? "Saving..." : "Save Vault Details"}
            </button>
          </form>

          {/* Change Master Password & Keyfile */}
          <form
            onSubmit={handleChangeMasterCredentials}
            className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-4 border-amber-500/25"
          >
            <div className="flex items-start justify-between gap-2">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <KeyRound className="w-4 h-4 text-amber-400" />
                  Change Master Password &amp; Keyfile
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Re-encrypts this vault atomically with a new Master Password and/or Keyfile v2.0 XML.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowMasterGen(!showMasterGen)}
                className="text-[11px] font-semibold cyber-accent-text hover:opacity-80 flex items-center gap-1 shrink-0"
              >
                <Wand2 className="w-3.5 h-3.5" />
                {showMasterGen ? "Hide Gen" : "Generate"}
              </button>
            </div>

            {status.has_master_password && (
              <div>
                <label className="block text-xs text-slate-400 mb-1">
                  Current Master Password *
                </label>
                <div className="relative">
                  <input
                    type={showMasterPw ? "text" : "password"}
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    placeholder="Verify current master password..."
                    autoComplete="off"
                    className="w-full rounded-xl bg-[#07090F] border border-slate-700 pl-3 pr-10 py-2 text-sm font-mono text-white focus:outline-none focus:border-cyan-400"
                  />
                  <button
                    type="button"
                    onClick={() => setShowMasterPw(!showMasterPw)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400"
                  >
                    {showMasterPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-slate-400 mb-1">New Master Password</label>
                <input
                  type={showMasterPw ? "text" : "password"}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter strong new password..."
                  autoComplete="off"
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-sm font-mono text-white focus:outline-none focus:border-cyan-400"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">
                  Confirm New Password
                </label>
                <input
                  type={showMasterPw ? "text" : "password"}
                  value={confirmNewPassword}
                  onChange={(e) => setConfirmNewPassword(e.target.value)}
                  placeholder="Repeat new password..."
                  autoComplete="off"
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-sm font-mono text-white focus:outline-none focus:border-cyan-400"
                />
              </div>
            </div>

            {newPwEntropy && (
              <div className="space-y-1">
                <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${entropyBarColor}`}
                    style={{ width: `${newPwEntropy.score}%` }}
                  />
                </div>
                <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                  <span>{newPwEntropy.strength}</span>
                  <span>
                    {newPwEntropy.entropy_bits}b ·{" "}
                    <span className="text-cyan-300">{newPwEntropy.post_quantum_bits}b PQ</span>
                  </span>
                </div>
              </div>
            )}

            {showMasterGen && (
              <div className="rounded-xl bg-[#07090F] border cyber-accent-border p-3.5">
                <GeneratorPanel
                  onCopy={onCopy}
                  onApply={(pw) => {
                    setNewPassword(pw);
                    setConfirmNewPassword(pw);
                    setShowMasterPw(true);
                    setShowMasterGen(false);
                  }}
                />
              </div>
            )}

            {/* Keyfile Control */}
            <div className="space-y-2 pt-2 border-t border-slate-800/80">
              <label className="block text-xs text-slate-400">
                Keyfile Setting{" "}
                <span className="text-cyan-300 font-mono">
                  ({status.has_keyfile ? "Currently attached" : "None attached"})
                </span>
              </label>
              <div className="grid grid-cols-3 gap-1.5">
                {[
                  { id: "keep" as const, label: "Keep Current" },
                  { id: "set" as const, label: "Attach / Replace" },
                  { id: "remove" as const, label: "Remove Keyfile" },
                ].map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setKeyfileAction(opt.id)}
                    className={`py-1.5 px-2 rounded-lg text-[11px] font-medium border transition ${
                      keyfileAction === opt.id
                        ? "bg-cyan-500/15 border-cyan-400/50 text-cyan-200"
                        : "bg-[#07090F] border-slate-800 text-slate-400"
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
              {keyfileAction === "set" && (
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={newKeyfilePath}
                    onChange={(e) => setNewKeyfilePath(e.target.value)}
                    placeholder="Select .keyx / .xml keyfile..."
                    className="flex-1 min-w-0 rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-xs font-mono text-slate-200"
                  />
                  <button
                    type="button"
                    onClick={async () => {
                      const picked = await pickOpenKeyfile();
                      if (picked) setNewKeyfilePath(picked);
                    }}
                    className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-slate-200 shrink-0"
                  >
                    Browse
                  </button>
                </div>
              )}
            </div>

            <button
              type="submit"
              disabled={rotatingCreds}
              className="px-4 py-2.5 rounded-xl cyber-btn-primary text-xs font-bold flex items-center gap-2 transition disabled:opacity-50"
            >
              <KeyRound className="w-4 h-4" />
              {rotatingCreds ? "Re-encrypting Vault..." : "Update Master Credentials"}
            </button>
          </form>

          {/* Biometric Vault Unlock (Mobile) */}
          {isMobilePlatform() && (
            <div className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-3 border-emerald-500/30">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Fingerprint className="w-4 h-4 text-emerald-400" />
                    Biometric Vault Unlock
                  </h3>
                  <p className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">
                    Seals this vault&apos;s Master Password inside a ChaCha20-Poly1305 keyslot gated by native OS Fingerprint / Face ID.
                  </p>
                </div>
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded-full border shrink-0 ${
                    bioEnabled
                      ? "bg-emerald-500/15 text-emerald-300 border-emerald-400/40"
                      : "bg-slate-800 text-slate-400 border-slate-700"
                  }`}
                >
                  {bioEnabled ? "ENABLED" : "OFF"}
                </span>
              </div>

              <div className="flex flex-wrap gap-2.5">
                {!bioEnabled ? (
                  <button
                    type="button"
                    onClick={async () => {
                      setError(null);
                      setMessage(null);
                      try {
                        await vaultApi.enableBiometricUnlock();
                        setBioEnabled(true);
                        setMessage("Biometric Vault Unlock enabled for this vault.");
                      } catch (err) {
                        setError(String(err));
                      }
                    }}
                    className="px-4 py-2 rounded-xl bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-400/40 text-xs text-emerald-200 font-semibold flex items-center gap-2 transition"
                  >
                    <Fingerprint className="w-4 h-4" />
                    Bind Biometrics to This Vault
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={async () => {
                      setError(null);
                      setMessage(null);
                      try {
                        await vaultApi.disableBiometricUnlock();
                        setBioEnabled(false);
                        setMessage("Biometric keyslot wiped and revoked for this vault.");
                      } catch (err) {
                        setError(String(err));
                      }
                    }}
                    className="px-4 py-2 rounded-xl bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/40 text-xs text-rose-200 font-semibold flex items-center gap-2 transition"
                  >
                    Revoke &amp; Wipe Biometric Keyslot
                  </button>
                )}
              </div>
            </div>
          )}

          {/* Location, Move & Backup */}
          <div className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-3">
            <h3 className="text-sm font-bold text-white">File Location, Backup &amp; Keyfile</h3>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => setFolderModalMode("move")}
                className="px-3.5 py-2 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-400/35 text-xs text-cyan-200 font-semibold flex items-center gap-2"
              >
                <FolderInput className="w-4 h-4" />
                Move Vault Folder
              </button>
              <button
                type="button"
                onClick={handleExportBackup}
                className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-cyan-300 font-medium flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                Export .kdbx Backup
              </button>
              <button
                type="button"
                onClick={handleGenerateKeyfile}
                className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-violet-300 font-medium flex items-center gap-2"
              >
                <FileKey2 className="w-4 h-4" />
                Generate Keyfile v2.0
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================
          TAB 2: ENCRYPTION PROTOCOL & POST-QUANTUM ARMOR
         ============================================================ */}
      {section === "crypto" && (
        <div className="space-y-5 deck-animate">
          {/* Plain-Language Post-Quantum Explainer & Status Card */}
          <div className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-3.5 border-violet-500/35">
            <div className="flex items-start justify-between gap-2 flex-wrap">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Info className="w-4 h-4 text-violet-400 shrink-0" />
                How Quantum Protection Works in CipherPass
              </h3>
              <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                PQ ENGINE ACTIVE
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px] leading-relaxed">
              <div className="rounded-xl bg-[#07090F] border border-cyan-500/25 p-3 space-y-1.5">
                <div className="flex items-center justify-between gap-1">
                  <span className="font-bold text-cyan-300">
                    Layer 1 · Live .kdbx Vault
                  </span>
                  <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300">
                    ALWAYS ON
                  </span>
                </div>
                <p className="text-slate-300">
                  Uses <strong>{status.cipher ?? "ChaCha20"} (256-bit)</strong> or{" "}
                  <strong>AES-256</strong> + <strong>Argon2id</strong>. Why only those two?
                  256-bit symmetric ciphers are <strong>already quantum-resistant</strong> (Grover&apos;s
                  algorithm leaves 128-bit quantum security, unbreakable per NIST) and keep your{" "}
                  <code className="text-cyan-300">.kdbx</code> 100% compatible with KeePassXC &amp; KeePassDX.
                </p>
              </div>

              <div className="rounded-xl bg-[#07090F] border border-violet-500/30 p-3 space-y-1.5">
                <div className="flex items-center justify-between gap-1">
                  <span className="font-bold text-violet-300">
                    Layer 2 · FIPS 203 ML-KEM-1024
                  </span>
                  <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-300">
                    REAL RUST ENGINE
                  </span>
                </div>
                <p className="text-slate-300">
                  Real lattice-based NIST FIPS 203 (Category 5) asymmetric encryption wrapped around
                  your <code className="text-cyan-300">.kdbx</code> to create a double-armored{" "}
                  <code className="text-violet-300">.kdbx.pq</code> file for cloud sync or cold
                  backups. Even if someone steals the file, they need both your ML-KEM-1024 Secret Key
                  and your Master Password.
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2.5 pt-1">
              <button
                type="button"
                disabled={runningSelfTest}
                onClick={handleRunPqSelfTest}
                className="px-3.5 py-2 rounded-xl bg-violet-500/20 hover:bg-violet-500/30 border border-violet-400/40 text-xs font-semibold text-violet-200 flex items-center gap-1.5 transition"
              >
                <Play className="w-3.5 h-3.5" />
                {runningSelfTest
                  ? "Running ML-KEM-1024 Test..."
                  : "Verify ML-KEM-1024 Live on This Device"}
              </button>
              {pqSelfTest && (
                <div className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 rounded-lg px-3 py-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                  <span>
                    {pqSelfTest.passed ? "PASSED" : "FAILED"} · {pqSelfTest.elapsed_ms}ms · PK{" "}
                    {pqSelfTest.public_key_bytes}B / SK {pqSelfTest.secret_key_bytes}B · FP{" "}
                    {pqSelfTest.fingerprint}
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Layer 1: KDBX 4 Cipher, KDF & Session Security Editor */}
          <form onSubmit={handleSaveCrypto} className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-4">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 cyber-accent-text" />
                Layer 1 · Vault Encryption Protocol (KDBX 4)
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Changes re-encrypt your <code className="text-cyan-300">.kdbx</code> file atomically on disk.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              <div>
                <label className="block text-xs text-slate-400 mb-1">
                  Outer Encryption Cipher (256-bit PQ-Safe)
                </label>
                <select
                  value={cipher}
                  onChange={(e) => setCipher(e.target.value as CipherAlgorithm)}
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-sm text-white"
                >
                  <option value="ChaCha20">ChaCha20 (256-bit · Recommended)</option>
                  <option value="Aes256Cbc">AES-256-CBC (256-bit)</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Argon2 KDF Variant</label>
                <select
                  value={kdfAlg}
                  onChange={(e) => setKdfAlg(e.target.value as KdfAlgorithm)}
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-sm text-white"
                >
                  <option value="Argon2id">Argon2id v0x13 (Hybrid · Recommended)</option>
                  <option value="Argon2d">Argon2d v0x13 (GPU-resistant)</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-3 gap-2.5">
              <div>
                <label className="block text-[11px] text-slate-400 mb-1">Memory (MiB ≥64)</label>
                <input
                  type="number"
                  min={64}
                  max={2048}
                  value={memoryMib}
                  onChange={(e) => setMemoryMib(Number(e.target.value))}
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-sm font-mono text-white"
                />
              </div>
              <div>
                <label className="block text-[11px] text-slate-400 mb-1">Rounds (≥3)</label>
                <input
                  type="number"
                  min={3}
                  max={100}
                  value={iterations}
                  onChange={(e) => setIterations(Number(e.target.value))}
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-sm font-mono text-white"
                />
              </div>
              <div>
                <label className="block text-[11px] text-slate-400 mb-1">Lanes (≥1)</label>
                <input
                  type="number"
                  min={1}
                  max={16}
                  value={parallelism}
                  onChange={(e) => setParallelism(Number(e.target.value))}
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-sm font-mono text-white"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 pt-2 border-t border-slate-800/80">
              <div>
                <label className="block text-xs text-slate-400 mb-1">
                  Inactivity Auto-Lock (Zeroizes RAM)
                </label>
                <select
                  value={autoLock}
                  onChange={(e) => setAutoLock(Number(e.target.value))}
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-sm text-white"
                >
                  <option value={60}>1 minute</option>
                  <option value={300}>5 minutes (Recommended)</option>
                  <option value={600}>10 minutes</option>
                  <option value={900}>15 minutes</option>
                  <option value={0}>Disabled</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">
                  Clipboard Auto-Clear Timer
                </label>
                <select
                  value={clipClear}
                  onChange={(e) => setClipClear(Number(e.target.value))}
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-sm text-white"
                >
                  <option value={15}>15 seconds</option>
                  <option value={30}>30 seconds (Recommended)</option>
                  <option value={60}>60 seconds</option>
                </select>
              </div>
            </div>

            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2.5 rounded-xl cyber-btn-primary font-bold text-xs flex items-center gap-2 transition"
            >
              <Save className="w-4 h-4" />
              {saving ? "Re-encrypting Vault..." : "Apply & Re-Encrypt Vault"}
            </button>
          </form>

          {/* Layer 2: Post-Quantum Vault Armor Workshop (.kdbx.pq) */}
          <div className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-4 border-violet-500/30">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Atom className="w-4 h-4 text-violet-400" />
                  Layer 2 · Post-Quantum Vault Armor (.kdbx.pq)
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  3-step workflow: (1) Generate keys &amp; save your Secret Key offline, (2) Seal your vault to <code className="text-violet-300">.kdbx.pq</code>, (3) Unseal anytime back to <code className="text-cyan-300">.kdbx</code>.
                </p>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-violet-500/15 text-violet-300 border border-violet-400/30 shrink-0">
                FIPS 203
              </span>
            </div>

            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={async () => {
                  setError(null);
                  setMessage(null);
                  try {
                    const kp = await vaultApi.generatePqKeypair();
                    setPqKeypair(kp);
                    setPqPubKey(kp.public_key_b64);
                    setPqSecKey(kp.secret_key_b64);
                    setMessage(
                      `Generated ML-KEM-1024 keypair (Fingerprint: ${kp.fingerprint}). Copy and store your Secret Key safely offline!`
                    );
                  } catch (err) {
                    setError(String(err));
                  }
                }}
                className="px-3.5 py-2 rounded-xl bg-violet-500/20 hover:bg-violet-500/30 border border-violet-400/40 text-xs text-violet-200 font-semibold flex items-center gap-1.5"
              >
                <Atom className="w-3.5 h-3.5" />
                1. Generate Keypair
              </button>

              <button
                type="button"
                disabled={sealingPq}
                onClick={handleSealPq}
                className="px-3.5 py-2 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-400/30 text-xs text-cyan-200 font-semibold flex items-center gap-1.5"
              >
                <Lock className="w-3.5 h-3.5" />
                {sealingPq ? "Sealing..." : "2. Seal Vault → .kdbx.pq"}
              </button>

              <button
                type="button"
                onClick={async () => {
                  setError(null);
                  setMessage(null);
                  if (!pqSecKey.trim()) {
                    setError("Paste your ML-KEM-1024 Secret Key to unseal.");
                    return;
                  }
                  const src = await pickOpenPqFile();
                  if (!src) return;
                  const dest = await pickSaveKdbxFile("CipherPass_Unsealed.kdbx");
                  if (!dest) return;
                  try {
                    await vaultApi.unsealPqArmoredVault(src, dest, pqSecKey.trim());
                    setMessage(`Unsealed .kdbx.pq back to standard KDBX 4 at ${dest}`);
                  } catch (err) {
                    setError(String(err));
                  }
                }}
                className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-slate-200 font-medium flex items-center gap-1.5"
              >
                <Unlock className="w-3.5 h-3.5" />
                3. Unseal .kdbx.pq → .kdbx
              </button>
            </div>

            {pqKeypair && (
              <div className="text-[11px] font-mono text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 rounded-lg px-3 py-2">
                Public Key SHA3-512 Fingerprint: {pqKeypair.fingerprint}
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-[11px] text-slate-400">
                    ML-KEM-1024 Public Key (Base64)
                  </label>
                  {pqPubKey && (
                    <button
                      type="button"
                      onClick={() => onCopy(pqPubKey, "ML-KEM-1024 Public Key")}
                      className="text-[10px] text-cyan-300 flex items-center gap-1"
                    >
                      <Copy className="w-3 h-3" /> Copy
                    </button>
                  )}
                </div>
                <textarea
                  rows={2}
                  value={pqPubKey}
                  onChange={(e) => setPqPubKey(e.target.value)}
                  placeholder="Encapsulation key (1568 bytes)..."
                  className="w-full rounded-lg bg-[#07090F] border border-slate-700 px-2.5 py-1.5 text-[10px] font-mono text-cyan-200"
                />
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-[11px] text-slate-400">
                    ML-KEM-1024 Secret Key (Keep Offline)
                  </label>
                  {pqSecKey && (
                    <button
                      type="button"
                      onClick={() => onCopy(pqSecKey, "ML-KEM-1024 Secret Key")}
                      className="text-[10px] text-violet-300 flex items-center gap-1"
                    >
                      <Copy className="w-3 h-3" /> Copy
                    </button>
                  )}
                </div>
                <textarea
                  rows={2}
                  value={pqSecKey}
                  onChange={(e) => setPqSecKey(e.target.value)}
                  placeholder="Decapsulation key (3168 bytes)..."
                  className="w-full rounded-lg bg-[#07090F] border border-slate-700 px-2.5 py-1.5 text-[10px] font-mono text-violet-200"
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================
          TAB 3: APPEARANCE — 4 COMPLETE GUI STYLES + 9 LIGHT/DARK THEMES
         ============================================================ */}
      {section === "appearance" && (
        <div className="space-y-5 deck-animate">
          <div className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-3.5">
            <div>
              <h3 className="text-sm font-bold text-white">Graphic User Interface Style (4)</h3>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Transform the entire app layout, card geometry, shadows, glass blur, and motion language instantly.
              </p>
            </div>
            <UiStylePicker uiStyle={uiStyle} onChange={onUiStyleChange} />
          </div>

          <div className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-3.5">
            <div>
              <h3 className="text-sm font-bold text-white">Color Palette (4 Light + 5 Dark)</h3>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Mix any of the 9 high-contrast color palettes with any GUI style above.
              </p>
            </div>
            <ThemePicker theme={theme} onChange={onThemeChange} />
          </div>
        </div>
      )}

      {/* Shared Folder Picker Modal for Move / Backup / PQ Seal */}
      <FolderPickerModal
        open={folderModalMode !== null}
        title={
          folderModalMode === "pq-seal"
            ? "Choose Folder for Quantum .kdbx.pq Backup"
            : folderModalMode === "backup"
            ? "Choose Folder for .kdbx Backup"
            : "Move Vault to Another Folder"
        }
        requiredExtension={folderModalMode === "pq-seal" ? ".kdbx.pq" : ".kdbx"}
        defaultFileName={
          folderModalMode === "pq-seal"
            ? `${safeBaseName}_Quantum.kdbx.pq`
            : folderModalMode === "backup"
            ? `${safeBaseName}_Backup.kdbx`
            : `${safeBaseName}.kdbx`
        }
        onSelectFullPath={async (destPath) => {
          setError(null);
          setMessage(null);
          const mode = folderModalMode;
          try {
            if (mode === "move") {
              const updated = await vaultApi.moveVaultToPath(destPath);
              onStatusUpdated(updated);
              setMessage(`Vault moved & saved atomically to ${updated.path}`);
            } else if (mode === "backup") {
              const saved = await vaultApi.exportVaultBackup(destPath);
              setMessage(`Atomic KDBX 4 backup exported to ${saved}`);
            } else if (mode === "pq-seal") {
              setSealingPq(true);
              const saved = await vaultApi.exportPqArmoredVault(
                destPath,
                pqPubKey.trim()
              );
              setMessage(`Vault sealed with FIPS 203 ML-KEM-1024 to ${saved}`);
            }
          } catch (err) {
            setError(String(err));
          } finally {
            setSealingPq(false);
          }
        }}
        onClose={() => setFolderModalMode(null)}
      />

      {/* Footer Notice */}
      <div className="rounded-xl bg-[#0D111A] border border-slate-800 p-4 text-[11px] text-slate-400 space-y-1">
        <div className="text-slate-300 font-semibold">
          CipherPass · All Rights Reserved — Private Personal Use
        </div>
        <div>
          Engine: Pure Rust (<code className="text-cyan-300">#![forbid(unsafe_code)]</code>), KDBX 4 / 4.1 + NIST FIPS 203 ML-KEM-1024, zero telemetry, zero network sockets.
        </div>
      </div>
    </div>
  );
};
