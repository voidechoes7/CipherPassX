import React, { useEffect, useState } from "react";
import {
  ArrowDownUp,
  Atom,
  CheckCircle2,
  Clock,
  Copy,
  Database,
  Download,
  Eye,
  EyeOff,
  FileJson,
  FileKey2,
  FileSpreadsheet,
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
  Smartphone,
  Trash2,
  Type,
  Unlock,
  Upload,
  Wand2,
} from "lucide-react";
import {
  applyScreenProtection,
  isMobilePlatform,
  loadBioGateAppStorage,
  loadHideRecentVaults,
  loadScreenProtection,
  pickOpenCsvFile,
  pickOpenJsonFile,
  pickOpenKdbxFile,
  pickOpenKeyfile,
  pickOpenPqFile,
  pickOpenPqKeyFile,
  pickSaveJsonFile,
  pickSaveKdbxFile,
  pickSaveKeyfile,
  pickSavePqFile,
  pickSavePqKeyFile,
  saveBioGateAppStorage,
  saveHideRecentVaults,
  vaultApi,
} from "../api/vaultApi";
import { FONT_SCALES, type FontScaleId, type ThemeId, type UiStyleId } from "../themes";
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
  fontScale: FontScaleId;
  maskSubtitles: boolean;
  bgLockSeconds: number;
  onThemeChange: (t: ThemeId) => void;
  onUiStyleChange: (s: UiStyleId) => void;
  onFontScaleChange: (f: FontScaleId) => void;
  onMaskSubtitlesChange: (m: boolean) => void;
  onBgLockSecondsChange: (s: number) => void;
  onStatusUpdated: (status: VaultStatus) => void;
  onVaultDataChanged: () => void;
  onCopy: (secret: string, label: string) => void;
}

type SettingsSection = "vault" | "crypto" | "interchange" | "appearance";

export const SettingsView: React.FC<Props> = ({
  status,
  theme,
  uiStyle,
  fontScale,
  maskSubtitles,
  bgLockSeconds,
  onThemeChange,
  onUiStyleChange,
  onFontScaleChange,
  onMaskSubtitlesChange,
  onBgLockSecondsChange,
  onStatusUpdated,
  onVaultDataChanged,
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
  const [hideRecents, setHideRecents] = useState<boolean>(() => loadHideRecentVaults());
  const [bioGateAppStorage, setBioGateAppStorage] = useState<boolean>(() =>
    loadBioGateAppStorage()
  );
  const [screenProtection, setScreenProtection] = useState<boolean>(() => loadScreenProtection());

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

  // Import / Export State
  const [bwJsonPath, setBwJsonPath] = useState("");
  const [bwJsonPassword, setBwJsonPassword] = useState("");
  const [kdbxImportPath, setKdbxImportPath] = useState("");
  const [kdbxImportPassword, setKdbxImportPassword] = useState("");
  const [kdbxImportKeyfile, setKdbxImportKeyfile] = useState("");
  const [exportJsonPassword, setExportJsonPassword] = useState("");
  const [exportJsonConfirm, setExportJsonConfirm] = useState("");
  const [showExportPw, setShowExportPw] = useState(false);
  const [busyInterchange, setBusyInterchange] = useState(false);

  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // NIST FIPS 203 ML-KEM-1024 Post-Quantum Armor state
  const [pqKeypair, setPqKeypair] = useState<MlKem1024Keypair | null>(null);
  const [pqPubKey, setPqPubKey] = useState("");
  const [pqSecKey, setPqSecKey] = useState("");
  const [showPqSecKey, setShowPqSecKey] = useState(false);
  const [pqSelfTest, setPqSelfTest] = useState<PqSelfTestResult | null>(null);
  const [runningSelfTest, setRunningSelfTest] = useState(false);
  const [sealingPq, setSealingPq] = useState(false);

  // Biometric & Folder Modal states
  const [bioEnabled, setBioEnabled] = useState(false);
  const [folderModalMode, setFolderModalMode] = useState<
    null | "move" | "backup" | "pq-seal" | "json-export" | "pq-save-pub" | "pq-save-sec"
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
    const dest = await pickSaveKdbxFile(`${safeBaseName}_Backup.kdbx`);
    if (!dest) return;
    try {
      const saved = await vaultApi.exportVaultBackup(dest);
      setMessage(`Atomic KDBX 4 backup exported to ${saved}`);
    } catch (err) {
      setError(String(err));
    }
  };

  const handleExportEncryptedJson = async () => {
    setMessage(null);
    setError(null);
    if (exportJsonPassword.length < 8) {
      setError("Choose an export password of at least 8 characters for Encrypted JSON.");
      return;
    }
    if (exportJsonPassword !== exportJsonConfirm) {
      setError("Export passwords do not match.");
      return;
    }
    if (isMobilePlatform()) {
      setFolderModalMode("json-export");
      return;
    }
    const dest = await pickSaveJsonFile(`${safeBaseName}_Encrypted.json`);
    if (!dest) return;
    setBusyInterchange(true);
    try {
      const saved = await vaultApi.exportEncryptedJsonFile(dest, exportJsonPassword);
      setExportJsonPassword("");
      setExportJsonConfirm("");
      setMessage(
        `Cross-platform Encrypted JSON (Argon2id + AES-256-CBC + HMAC-SHA256) saved to ${saved}`
      );
    } catch (err) {
      setError(String(err));
    } finally {
      setBusyInterchange(false);
    }
  };

  const handleImportBitwardenJson = async () => {
    setMessage(null);
    setError(null);
    let src = bwJsonPath.trim();
    if (!src) {
      const picked = await pickOpenJsonFile();
      if (!picked) return;
      src = picked;
      setBwJsonPath(picked);
    }
    setBusyInterchange(true);
    try {
      const summary = await vaultApi.importBitwardenJsonFile(
        src,
        bwJsonPassword || null
      );
      const updated = await vaultApi.getStatus();
      onStatusUpdated(updated);
      onVaultDataChanged();
      setBwJsonPassword("");
      setMessage(
        `Imported ${summary.imported_entries} entries & ${summary.created_folders} folders from ${summary.source_format}. Saved atomically to your KDBX 4 vault!`
      );
    } catch (err) {
      setError(String(err));
    } finally {
      setBusyInterchange(false);
    }
  };

  const handleImportCsv = async () => {
    setMessage(null);
    setError(null);
    const picked = await pickOpenCsvFile();
    if (!picked) return;
    setBusyInterchange(true);
    try {
      const summary = await vaultApi.importCsvFile(picked);
      const updated = await vaultApi.getStatus();
      onStatusUpdated(updated);
      onVaultDataChanged();
      setMessage(
        `Imported ${summary.imported_entries} entries & ${summary.created_folders} folders from ${summary.source_format}.`
      );
    } catch (err) {
      setError(String(err));
    } finally {
      setBusyInterchange(false);
    }
  };

  const handleImportKdbx = async () => {
    setMessage(null);
    setError(null);
    let src = kdbxImportPath.trim();
    if (!src) {
      const picked = await pickOpenKdbxFile();
      if (!picked) return;
      src = picked;
      setKdbxImportPath(picked);
    }
    if (!kdbxImportPassword && !kdbxImportKeyfile.trim()) {
      setError("Enter the Master Password (and/or Keyfile) of the KeePass .kdbx file to merge.");
      return;
    }
    setBusyInterchange(true);
    try {
      const summary = await vaultApi.importKdbxIntoVault(
        src,
        kdbxImportPassword || null,
        kdbxImportKeyfile.trim() || null
      );
      const updated = await vaultApi.getStatus();
      onStatusUpdated(updated);
      onVaultDataChanged();
      setKdbxImportPassword("");
      setMessage(
        `Merged ${summary.imported_entries} entries & ${summary.created_folders} folders from KeePass KDBX 4 into your open vault!`
      );
    } catch (err) {
      setError(String(err));
    } finally {
      setBusyInterchange(false);
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
    const dest = await pickSavePqFile(`${safeBaseName}_Quantum.kdbx.pq`);
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
      {/* Header + 4-Section Segmented Switcher */}
      <div className="space-y-3">
        <div>
          <h2 className="text-lg sm:text-xl font-bold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 cyber-accent-text" />
            Vault Properties, Migration &amp; GUI
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Manage Master Password, encryption protocol, Bitwarden/KeePass migration, encrypted exports, and themes.
          </p>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5 p-1 rounded-xl bg-[#0D111A] border border-slate-800">
          {[
            { id: "vault" as const, label: "Vault & Key", icon: Database },
            { id: "crypto" as const, label: "Crypto & PQ", icon: Atom },
            { id: "interchange" as const, label: "Import / Export", icon: ArrowDownUp },
            { id: "appearance" as const, label: "Themes & GUI", icon: Palette },
          ].map((tab) => {
            const Icon = tab.icon;
            const active = section === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => {
                  if (section === "crypto" && tab.id !== "crypto") {
                    setPqKeypair(null);
                    setPqSecKey("");
                    setShowPqSecKey(false);
                  }
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
          TAB 1: VAULT PROPERTIES, MASTER PASSWORD & PRIVACY
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

          {/* Privacy, Clipboard & Device Protection Controls */}
          <div className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 cyber-accent-text" />
              Privacy, Clipboard &amp; Device Protection
            </h3>

            {/* 0. Clipboard Auto-Clear Limit (Instant & Persisted) */}
            <div className="space-y-2.5 pt-1">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-xs font-semibold text-white flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 cyber-accent-text" />
                    Clipboard Auto-Clear Limit
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">
                    Applies to all copied secrets — including <strong>press-and-hold</strong> quick copy in your vault list. Saved automatically across restarts.
                  </p>
                </div>
                <span className="text-xs font-mono font-bold text-cyan-300 bg-cyan-500/10 border border-cyan-400/30 px-2.5 py-1 rounded-lg shrink-0">
                  {clipClear >= 60 && clipClear % 60 === 0
                    ? `${clipClear / 60}m`
                    : `${clipClear}s`}
                </span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {[
                  { secs: 10, label: "10s" },
                  { secs: 15, label: "15s" },
                  { secs: 30, label: "30s" },
                  { secs: 45, label: "45s" },
                  { secs: 60, label: "60s" },
                  { secs: 120, label: "2 min" },
                  { secs: 300, label: "5 min" },
                ].map((opt) => (
                  <button
                    key={opt.secs}
                    type="button"
                    onClick={async () => {
                      setClipClear(opt.secs);
                      setError(null);
                      try {
                        const updated = await vaultApi.updateSecuritySettings({
                          clipboard_clear_seconds: opt.secs,
                        });
                        onStatusUpdated(updated);
                        setMessage(
                          `Clipboard auto-clear set to ${opt.label} (saved persistently).`
                        );
                      } catch (err) {
                        setError(String(err));
                      }
                    }}
                    className={`px-3 py-1.5 rounded-xl text-xs font-semibold border transition ${
                      clipClear === opt.secs
                        ? "cyber-btn-primary border-cyan-400/60"
                        : "bg-[#07090F] border-slate-700/80 text-slate-300 hover:border-cyan-400/40 hover:text-white"
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {/* 1. Entry List Privacy Mask */}
            <div className="flex items-start justify-between gap-3 pt-3 border-t border-slate-800/80">
              <div>
                <div className="text-xs font-semibold text-white flex items-center gap-1.5">
                  {maskSubtitles ? (
                    <EyeOff className="w-3.5 h-3.5 cyber-accent-text" />
                  ) : (
                    <Eye className="w-3.5 h-3.5 cyber-accent-text" />
                  )}
                  Entry List Privacy Mask
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">
                  Passwords are never displayed in the entry list. Enable this to also mask usernames and URLs as <code className="text-cyan-300">••••••••</code> until you tap an entry.
                </p>
              </div>
              <button
                type="button"
                onClick={() => {
                  const next = !maskSubtitles;
                  onMaskSubtitlesChange(next);
                  setMessage(
                    next
                      ? "Entry list privacy mask enabled — usernames & URLs are hidden."
                      : "Entry list privacy mask disabled."
                  );
                }}
                className={`px-3 py-1.5 rounded-xl text-xs font-semibold border shrink-0 transition ${
                  maskSubtitles
                    ? "bg-emerald-500/20 border-emerald-400/50 text-emerald-200"
                    : "bg-slate-800 border-slate-700 text-slate-300"
                }`}
              >
                {maskSubtitles ? "Masked" : "Visible"}
              </button>
            </div>

            {/* 2. Background / Minimize Auto-Lock */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pt-3 border-t border-slate-800/80">
              <div>
                <div className="text-xs font-semibold text-white flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 cyber-accent-text" />
                  Background / Minimize Auto-Lock
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">
                  Automatically lock &amp; zeroize RAM when switching apps or minimizing CipherPass.
                </p>
              </div>
              <select
                value={bgLockSeconds}
                onChange={(e) => {
                  const secs = Number(e.target.value);
                  onBgLockSecondsChange(secs);
                  setMessage(
                    secs === 0
                      ? "Background auto-lock disabled."
                      : secs === 1
                      ? "Vault will lock immediately when minimized or switched to background."
                      : `Vault will lock after ${secs}s in background.`
                  );
                }}
                className="rounded-xl bg-[#07090F] border border-slate-700 px-3 py-1.5 text-xs text-white shrink-0"
              >
                <option value={1}>Immediately</option>
                <option value={30}>After 30 seconds</option>
                <option value={60}>After 60 seconds</option>
                <option value={0}>Off (inactivity only)</option>
              </select>
            </div>

            {/* 3. Android Screen Protection (FLAG_SECURE) */}
            {isMobilePlatform() && (
              <div className="flex items-start justify-between gap-3 pt-3 border-t border-slate-800/80">
                <div>
                  <div className="text-xs font-semibold text-white flex items-center gap-1.5">
                    <Smartphone className="w-3.5 h-3.5 text-emerald-400" />
                    Anti-Screenshot &amp; Recents Blanking (FLAG_SECURE)
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">
                    Blocks Android screenshots, screen recording, and blanks the app preview in the Recent Apps switcher.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    const next = !screenProtection;
                    setScreenProtection(next);
                    applyScreenProtection(next);
                    setMessage(
                      next
                        ? "Android FLAG_SECURE enabled — screenshots & recents preview blocked."
                        : "Android FLAG_SECURE disabled — screenshots are temporarily allowed."
                    );
                  }}
                  className={`px-3 py-1.5 rounded-xl text-xs font-semibold border shrink-0 transition ${
                    screenProtection
                      ? "bg-emerald-500/20 border-emerald-400/50 text-emerald-200"
                      : "bg-amber-500/15 border-amber-400/40 text-amber-200"
                  }`}
                >
                  {screenProtection ? "Protected" : "Off"}
                </button>
              </div>
            )}

            {/* 4. Unlock Screen Privacy (Recent Vaults + Optional Biometric App Storage Gate) */}
            <div className="space-y-3 pt-3 border-t border-slate-800/80">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-xs font-semibold text-white flex items-center gap-1.5">
                    {hideRecents ? (
                      <EyeOff className="w-3.5 h-3.5 cyber-accent-text" />
                    ) : (
                      <Eye className="w-3.5 h-3.5 cyber-accent-text" />
                    )}
                    Hide Recent Vaults on Unlock Screen
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">
                    Completely hides recent vault names on the Unlock Screen with <strong>no Show button</strong>. Can only be re-enabled here after unlocking a vault.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    const next = !hideRecents;
                    setHideRecents(next);
                    saveHideRecentVaults(next);
                    setMessage(
                      next
                        ? "Recent vaults are strictly hidden on the Unlock Screen (re-enable only inside Settings)."
                        : "Recent vaults are now visible on the Unlock Screen."
                    );
                  }}
                  className={`px-3 py-1.5 rounded-xl text-xs font-semibold border shrink-0 transition ${
                    hideRecents
                      ? "bg-emerald-500/20 border-emerald-400/50 text-emerald-200"
                      : "bg-slate-800 border-slate-700 text-slate-300"
                  }`}
                >
                  {hideRecents ? "Strictly Hidden" : "Visible"}
                </button>
              </div>

              {isMobilePlatform() && (
                <div className="flex items-start justify-between gap-3 pt-2.5 border-t border-slate-800/60">
                  <div>
                    <div className="text-xs font-semibold text-white flex items-center gap-1.5">
                      <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
                      Biometric Lock on App Storage List
                    </div>
                    <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">
                      Optional extra privacy: require fingerprint / Face ID before showing `.kdbx` filenames inside App Storage on the Unlock Screen.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      const next = !bioGateAppStorage;
                      setBioGateAppStorage(next);
                      saveBioGateAppStorage(next);
                      setMessage(
                        next
                          ? "App Storage vault list now requires biometric verification."
                          : "App Storage vault list no longer requires biometrics."
                      );
                    }}
                    className={`px-3 py-1.5 rounded-xl text-xs font-semibold border shrink-0 transition ${
                      bioGateAppStorage
                        ? "bg-emerald-500/20 border-emerald-400/50 text-emerald-200"
                        : "bg-slate-800 border-slate-700 text-slate-300"
                    }`}
                  >
                    {bioGateAppStorage ? "Required" : "Off"}
                  </button>
                </div>
              )}

              <button
                type="button"
                onClick={async () => {
                  setError(null);
                  try {
                    await vaultApi.clearRecentVaults();
                    setMessage("Recent vaults history wiped.");
                  } catch (err) {
                    setError(String(err));
                  }
                }}
                className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-slate-300 inline-flex items-center gap-1.5 transition"
              >
                <Trash2 className="w-3.5 h-3.5 text-rose-400" />
                Clear Recent Vaults History
              </button>
            </div>
          </div>

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

          {/* Move Vault & Keyfile */}
          <div className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-3">
            <h3 className="text-sm font-bold text-white">File Location &amp; Keyfile</h3>
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
                  <strong>AES-256</strong> + <strong>Argon2id</strong>. 256-bit symmetric ciphers
                  are <strong>already quantum-resistant</strong> (128-bit Grover security per NIST)
                  and keep your <code className="text-cyan-300">.kdbx</code> 100% compatible with
                  KeePassXC &amp; KeePassDX.
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
                  Real lattice-based NIST FIPS 203 (Category 5) asymmetric envelope wrapped around
                  your <code className="text-cyan-300">.kdbx</code> to create a double-armored{" "}
                  <code className="text-violet-300">.kdbx.pq</code> file for cloud sync or cold
                  backups.
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
                  3-step workflow: (1) Generate keys &amp; save Secret Key offline, (2) Seal vault to <code className="text-violet-300">.kdbx.pq</code>, (3) Unseal anytime back to <code className="text-cyan-300">.kdbx</code>.
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
                <div className="flex items-center justify-between gap-1 mb-1 flex-wrap">
                  <label className="text-[11px] text-slate-400">
                    ML-KEM-1024 Public Key (Base64)
                  </label>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={async () => {
                        setError(null);
                        const picked = await pickOpenPqKeyFile();
                        if (!picked) return;
                        try {
                          const content = await vaultApi.readTextFile(picked);
                          setPqPubKey(content.trim());
                          setMessage(`Loaded ML-KEM-1024 Public Key from ${picked}`);
                        } catch (err) {
                          setError(String(err));
                        }
                      }}
                      className="text-[10px] text-slate-300 hover:text-cyan-300 flex items-center gap-0.5"
                    >
                      <Upload className="w-3 h-3" /> Load .pqpub
                    </button>
                    {pqPubKey && (
                      <>
                        <button
                          type="button"
                          onClick={async () => {
                            setError(null);
                            if (isMobilePlatform()) {
                              setFolderModalMode("pq-save-pub");
                              return;
                            }
                            const dest = await pickSavePqKeyFile(
                              `${safeBaseName}_MLKEM1024.pqpub`
                            );
                            if (!dest) return;
                            try {
                              const saved = await vaultApi.writeTextFile(dest, pqPubKey.trim());
                              setMessage(`Saved ML-KEM-1024 Public Key to ${saved}`);
                            } catch (err) {
                              setError(String(err));
                            }
                          }}
                          className="text-[10px] text-emerald-300 hover:underline flex items-center gap-0.5"
                        >
                          <Download className="w-3 h-3" /> Save
                        </button>
                        <button
                          type="button"
                          onClick={() => onCopy(pqPubKey, "ML-KEM-1024 Public Key")}
                          className="text-[10px] text-cyan-300 flex items-center gap-0.5"
                        >
                          <Copy className="w-3 h-3" /> Copy
                        </button>
                      </>
                    )}
                  </div>
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
                <div className="flex items-center justify-between gap-1 mb-1 flex-wrap">
                  <label className="text-[11px] text-slate-400">
                    ML-KEM-1024 Secret Key (Keep Offline)
                  </label>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={async () => {
                        setError(null);
                        const picked = await pickOpenPqKeyFile();
                        if (!picked) return;
                        try {
                          const content = await vaultApi.readTextFile(picked);
                          setPqSecKey(content.trim());
                          setMessage(`Loaded ML-KEM-1024 Secret Key from ${picked}`);
                        } catch (err) {
                          setError(String(err));
                        }
                      }}
                      className="text-[10px] text-slate-300 hover:text-violet-300 flex items-center gap-0.5"
                    >
                      <Upload className="w-3 h-3" /> Load .pqkey
                    </button>
                    {pqSecKey && (
                      <>
                        <button
                          type="button"
                          onClick={async () => {
                            setError(null);
                            if (isMobilePlatform()) {
                              setFolderModalMode("pq-save-sec");
                              return;
                            }
                            const dest = await pickSavePqKeyFile(
                              `${safeBaseName}_MLKEM1024_SECRET.pqkey`
                            );
                            if (!dest) return;
                            try {
                              const saved = await vaultApi.writeTextFile(dest, pqSecKey.trim());
                              setMessage(
                                `Saved ML-KEM-1024 Secret Key to ${saved} — move it to offline/cold storage!`
                              );
                            } catch (err) {
                              setError(String(err));
                            }
                          }}
                          className="text-[10px] text-emerald-300 hover:underline flex items-center gap-0.5"
                        >
                          <Download className="w-3 h-3" /> Save
                        </button>
                        <button
                          type="button"
                          onClick={() => setShowPqSecKey((v) => !v)}
                          className="text-[10px] text-slate-300 hover:text-violet-300 flex items-center gap-0.5"
                        >
                          {showPqSecKey ? (
                            <>
                              <EyeOff className="w-3 h-3" /> Hide
                            </>
                          ) : (
                            <>
                              <Eye className="w-3 h-3" /> Reveal
                            </>
                          )}
                        </button>
                        <button
                          type="button"
                          onClick={() => onCopy(pqSecKey, "ML-KEM-1024 Secret Key")}
                          className="text-[10px] text-violet-300 flex items-center gap-0.5"
                        >
                          <Copy className="w-3 h-3" /> Copy
                        </button>
                      </>
                    )}
                  </div>
                </div>
                {showPqSecKey ? (
                  <textarea
                    rows={2}
                    value={pqSecKey}
                    onChange={(e) => setPqSecKey(e.target.value)}
                    placeholder="Decapsulation key (3168 bytes)..."
                    className="w-full rounded-lg bg-[#07090F] border border-slate-700 px-2.5 py-1.5 text-[10px] font-mono text-violet-200"
                  />
                ) : (
                  <input
                    type="password"
                    value={pqSecKey}
                    onChange={(e) => setPqSecKey(e.target.value)}
                    placeholder="Decapsulation key (3168 bytes, masked)..."
                    autoComplete="off"
                    className="w-full rounded-lg bg-[#07090F] border border-slate-700 px-2.5 py-2 text-[10px] font-mono text-violet-200"
                  />
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================
          TAB 3: IMPORT (BITWARDEN / KEEPASS / CSV) & ENCRYPTED EXPORTS
         ============================================================ */}
      {section === "interchange" && (
        <div className="space-y-5 deck-animate">
          {/* Import from Bitwarden (JSON plain / encrypted + CSV) */}
          <div className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-4">
            <div className="flex items-start justify-between gap-2">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Upload className="w-4 h-4 cyber-accent-text" />
                  Import from Bitwarden (JSON / Encrypted JSON / CSV)
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">
                  Migrate 100% offline from Bitwarden. Preserves folders (including nested{" "}
                  <code className="text-cyan-300">Parent/Child</code>), Logins, 2FA/TOTP codes,
                  Cards, Secure Notes, and custom fields.
                </p>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-400/30 shrink-0">
                OFFLINE
              </span>
            </div>

            <div className="space-y-2.5">
              <div className="flex gap-2">
                <input
                  type="text"
                  value={bwJsonPath}
                  onChange={(e) => setBwJsonPath(e.target.value)}
                  placeholder="Select Bitwarden .json (plain or password-protected encrypted)..."
                  className="flex-1 min-w-0 rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-xs font-mono text-slate-200"
                />
                <button
                  type="button"
                  onClick={async () => {
                    const picked = await pickOpenJsonFile();
                    if (picked) setBwJsonPath(picked);
                  }}
                  className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-slate-200 shrink-0"
                >
                  Browse .json
                </button>
              </div>

              <div>
                <label className="block text-[11px] text-slate-400 mb-1">
                  Export Password (only required if the Bitwarden .json is Password-Protected Encrypted)
                </label>
                <input
                  type="password"
                  value={bwJsonPassword}
                  onChange={(e) => setBwJsonPassword(e.target.value)}
                  placeholder="Leave blank for unencrypted Bitwarden JSON..."
                  autoComplete="off"
                  className="w-full rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-xs font-mono text-white"
                />
              </div>

              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  disabled={busyInterchange}
                  onClick={handleImportBitwardenJson}
                  className="px-4 py-2 rounded-xl cyber-btn-primary text-xs font-bold flex items-center gap-1.5 transition disabled:opacity-50"
                >
                  <FileJson className="w-3.5 h-3.5" />
                  {busyInterchange ? "Importing..." : "Import Bitwarden / Encrypted .json"}
                </button>
                <button
                  type="button"
                  disabled={busyInterchange}
                  onClick={handleImportCsv}
                  className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-slate-200 font-medium flex items-center gap-1.5 transition"
                >
                  <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
                  Import CSV (Bitwarden / KeePass)
                </button>
              </div>
            </div>
          </div>

          {/* KeePass .kdbx Compatibility & Merge */}
          <div className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-3.5">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Database className="w-4 h-4 text-emerald-400" />
                Import / Merge KeePass (.kdbx) Vault
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">
                CipherPass opens <strong>KeePass 2.x, KeePassXC &amp; KeePassDX (KDBX 4 / 4.1)</strong>{" "}
                files natively from the Unlock Screen. You can also merge another <code className="text-cyan-300">.kdbx</code> file directly into this open vault below:
              </p>
            </div>

            <div className="flex gap-2">
              <input
                type="text"
                value={kdbxImportPath}
                onChange={(e) => setKdbxImportPath(e.target.value)}
                placeholder="Select external KeePass .kdbx file to merge..."
                className="flex-1 min-w-0 rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-xs font-mono text-slate-200"
              />
              <button
                type="button"
                onClick={async () => {
                  const picked = await pickOpenKdbxFile();
                  if (picked) setKdbxImportPath(picked);
                }}
                className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-slate-200 shrink-0"
              >
                Browse .kdbx
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <input
                type="password"
                value={kdbxImportPassword}
                onChange={(e) => setKdbxImportPassword(e.target.value)}
                placeholder="Source .kdbx Master Password..."
                autoComplete="off"
                className="w-full rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-xs font-mono text-white"
              />
              <div className="flex gap-1.5">
                <input
                  type="text"
                  value={kdbxImportKeyfile}
                  onChange={(e) => setKdbxImportKeyfile(e.target.value)}
                  placeholder="Optional source Keyfile..."
                  className="flex-1 min-w-0 rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-xs font-mono text-slate-200"
                />
                <button
                  type="button"
                  onClick={async () => {
                    const picked = await pickOpenKeyfile();
                    if (picked) setKdbxImportKeyfile(picked);
                  }}
                  className="px-2.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-slate-300 shrink-0"
                >
                  Key
                </button>
              </div>
            </div>

            <button
              type="button"
              disabled={busyInterchange}
              onClick={handleImportKdbx}
              className="px-4 py-2 rounded-xl bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-400/40 text-xs text-emerald-200 font-semibold flex items-center gap-1.5 transition disabled:opacity-50"
            >
              <Upload className="w-3.5 h-3.5" />
              {busyInterchange ? "Merging..." : "Merge KeePass .kdbx Into Current Vault"}
            </button>
          </div>

          {/* Cross-Platform Encrypted Exports (With Security Comparison) */}
          <div className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-4 border-cyan-500/30">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Download className="w-4 h-4 cyber-accent-text" />
                Cross-Platform Encrypted Export
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">
                Never export plaintext passwords. Choose the encrypted format that fits your workflow:
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[10px] leading-snug">
              <div className="rounded-xl bg-[#07090F] border border-cyan-500/30 p-2.5 space-y-1">
                <div className="font-bold text-cyan-300">Encrypted .json (Bitwarden v2)</div>
                <div className="text-slate-400">
                  Argon2id + AES-256-CBC + HMAC-SHA256. Opens in CipherPass, Bitwarden, Vaultwarden &amp; KeePassXC.
                </div>
              </div>
              <div className="rounded-xl bg-[#07090F] border border-emerald-500/30 p-2.5 space-y-1">
                <div className="font-bold text-emerald-300">KDBX 4 (.kdbx) · Best Daily</div>
                <div className="text-slate-400">
                  Industry standard ChaCha20/AES-256 + Argon2id. Opens natively across all KeePass apps.
                </div>
              </div>
              <div className="rounded-xl bg-[#07090F] border border-violet-500/30 p-2.5 space-y-1">
                <div className="font-bold text-violet-300">Quantum Armor (.kdbx.pq)</div>
                <div className="text-slate-400">
                  Double-layered NIST FIPS 203 ML-KEM-1024 + KDBX 4. Strongest for untrusted cloud backups.
                </div>
              </div>
            </div>

            {/* Password-Protected Encrypted JSON Form */}
            <div className="rounded-xl bg-[#07090F] border border-slate-800 p-3.5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-white">
                  Export Password-Protected Encrypted JSON (.json)
                </span>
                <button
                  type="button"
                  onClick={() => setShowExportPw(!showExportPw)}
                  className="text-[11px] text-slate-400 hover:text-cyan-300 flex items-center gap-1"
                >
                  {showExportPw ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  {showExportPw ? "Hide" : "Show"}
                </button>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <input
                  type={showExportPw ? "text" : "password"}
                  value={exportJsonPassword}
                  onChange={(e) => setExportJsonPassword(e.target.value)}
                  placeholder="Export encryption password (≥8 chars)..."
                  autoComplete="off"
                  className="w-full rounded-xl bg-[#0D111A] border border-slate-700 px-3 py-2 text-xs font-mono text-white"
                />
                <input
                  type={showExportPw ? "text" : "password"}
                  value={exportJsonConfirm}
                  onChange={(e) => setExportJsonConfirm(e.target.value)}
                  placeholder="Confirm export password..."
                  autoComplete="off"
                  className="w-full rounded-xl bg-[#0D111A] border border-slate-700 px-3 py-2 text-xs font-mono text-white"
                />
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  disabled={busyInterchange}
                  onClick={handleExportEncryptedJson}
                  className="px-4 py-2 rounded-xl cyber-btn-primary text-xs font-bold flex items-center gap-1.5 transition disabled:opacity-50"
                >
                  <FileJson className="w-3.5 h-3.5" />
                  {busyInterchange ? "Encrypting..." : "Export Encrypted .json"}
                </button>
                <button
                  type="button"
                  onClick={handleExportBackup}
                  className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-emerald-300 font-medium flex items-center gap-1.5 transition"
                >
                  <Download className="w-3.5 h-3.5" />
                  Export .kdbx Backup
                </button>
                <button
                  type="button"
                  onClick={() => setSection("crypto")}
                  className="px-3.5 py-2 rounded-xl bg-violet-500/15 hover:bg-violet-500/25 border border-violet-400/35 text-xs text-violet-200 font-medium flex items-center gap-1.5 transition"
                >
                  <Atom className="w-3.5 h-3.5" />
                  Seal .kdbx.pq (Quantum)
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================
          TAB 4: APPEARANCE — FONT SIZE, 4 GUI STYLES + 9 THEMES
         ============================================================ */}
      {section === "appearance" && (
        <div className="space-y-5 deck-animate">
          {/* Font Size / Text Scale */}
          <div className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-3">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Type className="w-4 h-4 cyber-accent-text" />
                Font Size &amp; Readability
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Scale text across the entire app (saved locally on this device).
              </p>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {FONT_SCALES.map((opt) => {
                const active = fontScale === opt.id;
                return (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => onFontScaleChange(opt.id)}
                    className={`rounded-xl border px-3 py-2.5 text-left transition ${
                      active
                        ? "bg-cyan-500/15 border-cyan-400/50 text-cyan-200"
                        : "bg-[#07090F] border-slate-800 text-slate-300 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-xs font-bold">{opt.label}</span>
                      <span className="text-[10px] font-mono text-slate-400">{opt.sample}</span>
                    </div>
                    <div
                      className="text-slate-400 mt-1"
                      style={{ fontSize: `${Math.round(11 * (parseFloat(opt.px) / 16))}px` }}
                    >
                      Aa Bb 123
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="cyber-panel rounded-2xl p-4 sm:p-5 space-y-3.5">
            <div>
              <h3 className="text-sm font-bold text-white">Graphic User Interface Style (4)</h3>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Transform the entire app layout, card geometry, shadows, Liquid Glass sliding dock, and motion language instantly.
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

      {/* Shared Folder Picker Modal for Move / Backup / PQ Seal / PQ Keys / Encrypted JSON Export */}
      <FolderPickerModal
        open={folderModalMode !== null}
        title={
          folderModalMode === "pq-save-pub"
            ? "Choose Folder for ML-KEM-1024 Public Key (.pqpub)"
            : folderModalMode === "pq-save-sec"
            ? "Choose Folder for ML-KEM-1024 Secret Key (.pqkey)"
            : folderModalMode === "json-export"
            ? "Choose Folder for Encrypted .json Export"
            : folderModalMode === "pq-seal"
            ? "Choose Folder for Quantum .kdbx.pq Backup"
            : folderModalMode === "backup"
            ? "Choose Folder for .kdbx Backup"
            : "Move Vault to Another Folder"
        }
        requiredExtension={
          folderModalMode === "pq-save-pub"
            ? ".pqpub"
            : folderModalMode === "pq-save-sec"
            ? ".pqkey"
            : folderModalMode === "json-export"
            ? ".json"
            : folderModalMode === "pq-seal"
            ? ".kdbx.pq"
            : ".kdbx"
        }
        defaultFileName={
          folderModalMode === "pq-save-pub"
            ? `${safeBaseName}_MLKEM1024.pqpub`
            : folderModalMode === "pq-save-sec"
            ? `${safeBaseName}_MLKEM1024_SECRET.pqkey`
            : folderModalMode === "json-export"
            ? `${safeBaseName}_Encrypted.json`
            : folderModalMode === "pq-seal"
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
            } else if (mode === "pq-save-pub") {
              const saved = await vaultApi.writeTextFile(destPath, pqPubKey.trim());
              setMessage(`Saved ML-KEM-1024 Public Key to ${saved}`);
            } else if (mode === "pq-save-sec") {
              const saved = await vaultApi.writeTextFile(destPath, pqSecKey.trim());
              setMessage(
                `Saved ML-KEM-1024 Secret Key to ${saved} — move it to offline/cold storage!`
              );
            } else if (mode === "json-export") {
              setBusyInterchange(true);
              const saved = await vaultApi.exportEncryptedJsonFile(
                destPath,
                exportJsonPassword
              );
              setExportJsonPassword("");
              setExportJsonConfirm("");
              setMessage(
                `Encrypted JSON (Argon2id + AES-256-CBC + HMAC-SHA256) exported to ${saved}`
              );
            }
          } catch (err) {
            setError(String(err));
          } finally {
            setSealingPq(false);
            setBusyInterchange(false);
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
          Engine: Pure Rust (<code className="text-cyan-300">#![forbid(unsafe_code)]</code>), KDBX 4 / 4.1 + NIST FIPS 203 ML-KEM-1024 + Bitwarden Encrypted JSON v2, zero telemetry, zero network sockets.
        </div>
      </div>
    </div>
  );
};
