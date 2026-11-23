import React, { useEffect, useState } from "react";
import {
  AlertTriangle,
  Database,
  Eye,
  EyeOff,
  FileKey2,
  Fingerprint,
  FolderOpen,
  Lock,
  PlusCircle,
  Sparkles,
  Wand2,
  WifiOff,
} from "lucide-react";
import {
  checkBiometricAvailable,
  isMobilePlatform,
  isTauriRuntime,
  pickFolder,
  pickOpenKdbxFile,
  pickOpenKeyfile,
  pickSaveKdbxFile,
  pickSaveKeyfile,
  vaultApi,
} from "../api/vaultApi";
import type { ThemeId } from "../themes";
import type {
  CipherAlgorithm,
  EntropyReport,
  KdfAlgorithm,
  LocalVaultInfo,
  VaultStatus,
} from "../types";
import { FolderPickerModal } from "./FolderPickerModal";
import { GeneratorPanel } from "./GeneratorPanel";
import { ThemePicker } from "./ThemePicker";

interface Props {
  theme: ThemeId;
  onThemeChange: (t: ThemeId) => void;
  onUnlocked: (status: VaultStatus) => void;
}

export const UnlockScreen: React.FC<Props> = ({ theme, onThemeChange, onUnlocked }) => {
  const [mode, setMode] = useState<"open" | "create">("open");
  const [defaultDir, setDefaultDir] = useState("");
  const [localVaults, setLocalVaults] = useState<LocalVaultInfo[]>([]);
  const [vaultPath, setVaultPath] = useState("");
  const [databaseName, setDatabaseName] = useState("CipherPass Vault");
  const [masterPassword, setMasterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showMasterGen, setShowMasterGen] = useState(false);
  const [entropy, setEntropy] = useState<EntropyReport | null>(null);
  const [keyfilePath, setKeyfilePath] = useState("");

  // KDBX 4 Post-Quantum Hardened Defaults
  const [cipher, setCipher] = useState<CipherAlgorithm>("ChaCha20");
  const [kdfAlgorithm, setKdfAlgorithm] = useState<KdfAlgorithm>("Argon2id");
  const [memoryMib, setMemoryMib] = useState(128);
  const [iterations, setIterations] = useState(4);
  const [parallelism, setParallelism] = useState(4);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [bioAvailable, setBioAvailable] = useState(false);
  const [hasBioSlot, setHasBioSlot] = useState(false);
  const [showFolderModal, setShowFolderModal] = useState(false);

  useEffect(() => {
    if (!isTauriRuntime()) return;
    checkBiometricAvailable().then(setBioAvailable).catch(() => {});
    vaultApi
      .getDefaultVaultDir()
      .then((dir) => setDefaultDir(dir))
      .catch(() => {});
    vaultApi
      .listLocalVaults()
      .then((list) => {
        setLocalVaults(list);
        if (list.length > 0) {
          setVaultPath((prev) => prev || list[0].path);
        }
      })
      .catch(() => {});
  }, []);

  // Check if selected vault has a biometric-bound ChaCha20-Poly1305 keyslot
  useEffect(() => {
    if (!isTauriRuntime() || mode !== "open" || !vaultPath.trim()) {
      setHasBioSlot(false);
      return;
    }
    let active = true;
    vaultApi
      .hasBiometricSlot(vaultPath.trim())
      .then((exists) => {
        if (active) setHasBioSlot(exists);
      })
      .catch(() => {
        if (active) setHasBioSlot(false);
      });
    return () => {
      active = false;
    };
  }, [mode, vaultPath]);

  // Auto-fill guaranteed writable local path when switching to Create mode
  useEffect(() => {
    if (mode === "create" && defaultDir) {
      const safeName =
        databaseName
          .trim()
          .replace(/[^a-zA-Z0-9_-]+/g, "_")
          .replace(/^_+|_+$/g, "") || "CipherPass_Vault";
      const sep = defaultDir.includes("\\") ? "\\" : "/";
      const expected = `${defaultDir}${sep}${safeName}.kdbx`;
      setVaultPath((curr) =>
        !curr || curr.startsWith(defaultDir) || curr.startsWith("content://")
          ? expected
          : curr
      );
    }
  }, [mode, databaseName, defaultDir]);

  // Live Master Password Entropy evaluation (classical + Post-Quantum Grover bound)
  useEffect(() => {
    if (!masterPassword) {
      setEntropy(null);
      return;
    }
    let active = true;
    vaultApi
      .evaluatePassword(masterPassword)
      .then((res) => {
        if (active) setEntropy(res);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [masterPassword]);

  const handleBrowseVault = async () => {
    setError(null);
    const safeName =
      databaseName
        .trim()
        .replace(/[^a-zA-Z0-9_-]+/g, "_")
        .replace(/^_+|_+$/g, "") || "CipherPass";
    const picked =
      mode === "open"
        ? await pickOpenKdbxFile()
        : await pickSaveKdbxFile(`${safeName}.kdbx`);
    if (picked) setVaultPath(picked);
  };

  const handlePickFolder = async () => {
    setError(null);
    const folder = await pickFolder();
    if (!folder) return;
    const safeName =
      databaseName
        .trim()
        .replace(/[^a-zA-Z0-9_-]+/g, "_")
        .replace(/^_+|_+$/g, "") || "CipherPass";
    const sep = folder.includes("\\") ? "\\" : "/";
    setVaultPath(`${folder.replace(/[\\/]+$/, "")}${sep}${safeName}.kdbx`);
  };

  const handleBiometricUnlock = async () => {
    if (!vaultPath.trim()) return;
    setError(null);
    setLoading(true);
    try {
      const status = await vaultApi.unlockVaultBiometric(vaultPath.trim());
      onUnlocked(status);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleBrowseKeyfile = async () => {
    setError(null);
    const picked = await pickOpenKeyfile();
    if (picked) setKeyfilePath(picked);
  };

  const handleGenerateKeyfile = async () => {
    setError(null);
    setInfo(null);
    let dest = await pickSaveKeyfile("CipherPass_Keyfile_v2.keyx");
    if (!dest && defaultDir) {
      const sep = defaultDir.includes("\\") ? "\\" : "/";
      dest = `${defaultDir}${sep}CipherPass_Keyfile_v2.keyx`;
    }
    if (!dest) return;
    try {
      const savedPath = await vaultApi.generateKeyfileToPath(dest);
      setKeyfilePath(savedPath);
      setInfo(
        "Generated 256-bit Keyfile v2.0 XML (KeePassXC / KeePassDX compatible). Keep a secure offline backup!"
      );
    } catch (e) {
      setError(String(e));
    }
  };

  const handleCopyGenerated = async (secret: string, label: string) => {
    try {
      const secs = await vaultApi.copySecretWithAutoClear(secret);
      setInfo(`${label} copied — clipboard clears in ${secs}s.`);
    } catch {
      setInfo(`${label} ready.`);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setInfo(null);

    const targetPath =
      vaultPath.trim() ||
      (mode === "create"
        ? `${databaseName.trim().replace(/\s+/g, "_") || "CipherPass_Vault"}.kdbx`
        : "");

    if (!targetPath) {
      setError("Please select a saved vault or browse for a .kdbx file.");
      return;
    }
    if (!masterPassword && !keyfilePath.trim()) {
      setError("Provide a Master Password, a Keyfile, or both.");
      return;
    }
    if (mode === "create" && masterPassword !== confirmPassword) {
      setError("Master passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      const status =
        mode === "open"
          ? await vaultApi.openVault({
              path: targetPath,
              master_password: masterPassword || null,
              keyfile_path: keyfilePath.trim() || null,
            })
          : await vaultApi.createVault({
              path: targetPath,
              database_name: databaseName.trim() || "CipherPass Vault",
              master_password: masterPassword || null,
              keyfile_path: keyfilePath.trim() || null,
              cipher,
              kdf_algorithm: kdfAlgorithm,
              memory_mib: memoryMib,
              iterations,
              parallelism,
            });
      setMasterPassword("");
      setConfirmPassword("");
      onUnlocked(status);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
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
    <div className="min-h-full w-full overflow-y-auto overflow-x-hidden safe-top safe-bottom cyber-grid flex flex-col items-center justify-start sm:justify-center px-3 py-4 sm:p-6 bg-[radial-gradient(ellipse_at_top,_rgba(0,240,255,0.10),_transparent_58%),radial-gradient(ellipse_at_bottom_right,_rgba(139,92,246,0.10),_transparent_55%)]">
      <div className="w-full max-w-xl cyber-panel rounded-2xl p-4 sm:p-7 space-y-5">
        {/* Top Status Strip — zero overflow on narrow mobile screens */}
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-1.5 text-[10px] font-mono px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 whitespace-nowrap">
            <WifiOff className="w-3 h-3 shrink-0" />
            100% OFFLINE
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono px-2.5 py-1 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-400/30 whitespace-nowrap">
              KDBX 4 · FIPS 203 PQ
            </span>
            <ThemePicker theme={theme} onChange={onThemeChange} compact />
          </div>
        </div>

        {/* Brand Header */}
        <div className="flex items-center gap-3.5">
          <div className="w-14 h-14 rounded-2xl overflow-hidden border cyber-accent-border cyber-glow shrink-0 bg-[#07090F]">
            <img src="/logo.png" alt="CipherPass" className="w-full h-full object-cover" />
          </div>
          <div className="min-w-0">
            <h1 className="text-2xl font-bold tracking-tight text-white truncate">
              CipherPass
            </h1>
            <p className="text-xs text-slate-400 mt-0.5 leading-snug">
              KeePassXC &amp; KeePassDX Interoperable · Pure Rust Core
            </p>
          </div>
        </div>

        {/* Mode Tabs */}
        <div className="grid grid-cols-2 gap-1.5 p-1 rounded-xl bg-[#07090F] border border-slate-800">
          <button
            type="button"
            onClick={() => {
              setMode("open");
              setShowMasterGen(false);
              setError(null);
            }}
            className={`flex items-center justify-center gap-1.5 py-2.5 px-2 rounded-lg text-xs sm:text-sm font-semibold transition whitespace-nowrap ${
              mode === "open"
                ? "bg-cyan-500/15 text-cyan-300 border border-cyan-400/35"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Lock className="w-4 h-4 shrink-0" />
            Unlock Vault
          </button>
          <button
            type="button"
            onClick={() => {
              setMode("create");
              setError(null);
            }}
            className={`flex items-center justify-center gap-1.5 py-2.5 px-2 rounded-lg text-xs sm:text-sm font-semibold transition whitespace-nowrap ${
              mode === "create"
                ? "bg-violet-500/15 text-violet-300 border border-violet-400/35"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <PlusCircle className="w-4 h-4 shrink-0" />
            Create Vault
          </button>
        </div>

        {!isTauriRuntime() && (
          <div className="rounded-xl bg-amber-500/10 border border-amber-500/30 p-3 text-xs text-amber-200 flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-amber-400" />
            <span>
              Browser preview detected. Native KDBX 4 encryption runs inside the Tauri 2 desktop/mobile binary.
            </span>
          </div>
        )}

        {/* Quick Saved Local Vaults Picker (Open Mode) */}
        {mode === "open" && localVaults.length > 0 && (
          <div className="space-y-1.5">
            <div className="text-[11px] font-medium text-slate-400 flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5 text-cyan-400" />
              Saved Device Vaults
            </div>
            <div className="flex flex-wrap gap-2">
              {localVaults.map((v) => {
                const selected = vaultPath === v.path;
                return (
                  <button
                    key={v.path}
                    type="button"
                    onClick={() => setVaultPath(v.path)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono border transition truncate max-w-full ${
                      selected
                        ? "bg-cyan-500/15 border-cyan-400/50 text-cyan-200"
                        : "bg-[#07090F] border-slate-800 text-slate-300 hover:border-slate-700"
                    }`}
                  >
                    {v.name}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {mode === "create" && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Vault Name
              </label>
              <input
                type="text"
                value={databaseName}
                onChange={(e) => setDatabaseName(e.target.value)}
                placeholder="My Personal Vault"
                className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-cyan-400"
              />
            </div>
          )}

          {/* Vault Path */}
          <div>
            <div className="flex items-center justify-between mb-1.5 gap-2">
              <label className="text-xs font-medium text-slate-300">
                KDBX 4 Database Location
              </label>
              {mode === "create" && defaultDir && (
                <span className="text-[10px] font-mono text-emerald-400">
                  Writable local storage ready
                </span>
              )}
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={vaultPath}
                onChange={(e) => setVaultPath(e.target.value)}
                placeholder={mode === "create" ? "CipherPass_Vault.kdbx" : "/path/to/vault.kdbx"}
                className="flex-1 min-w-0 rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2.5 text-xs sm:text-sm font-mono text-slate-100 focus:outline-none focus:border-cyan-400"
              />
              {mode === "create" && !isMobilePlatform() && (
                <button
                  type="button"
                  onClick={handlePickFolder}
                  className="px-3 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 shrink-0 transition"
                  title="Pick a folder for the new vault"
                >
                  <FolderOpen className="w-4 h-4 text-violet-400" />
                  Folder
                </button>
              )}
              <button
                type="button"
                onClick={handleBrowseVault}
                className="px-3 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 shrink-0 transition"
              >
                <FolderOpen className="w-4 h-4 text-cyan-400" />
                {mode === "create" && isMobilePlatform() ? "Save As" : "Browse"}
              </button>
            </div>
            {mode === "create" && isMobilePlatform() && (
              <p className="text-[10px] text-slate-400 mt-1 leading-snug">
                Default saves securely inside app storage (recommended). If you tap{" "}
                <span className="text-cyan-300 font-medium">Save As</span>, open your target folder and tap{" "}
                <span className="text-slate-200 font-medium">Save</span> at the bottom.
              </p>
            )}
          </div>

          {/* Master Password + KeePassDX-style Generator & Live Entropy Meter */}
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <label className="text-xs font-medium text-slate-300">
                Master Password
              </label>
              {mode === "create" && (
                <button
                  type="button"
                  onClick={() => setShowMasterGen(!showMasterGen)}
                  className="text-[11px] font-semibold cyber-accent-text hover:opacity-80 flex items-center gap-1 whitespace-nowrap"
                >
                  <Wand2 className="w-3.5 h-3.5" />
                  {showMasterGen ? "Hide Generator" : "Generate CSPRNG / Diceware"}
                </button>
              )}
            </div>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                value={masterPassword}
                onChange={(e) => setMasterPassword(e.target.value)}
                placeholder="Enter strong master password..."
                autoComplete="off"
                className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 pl-3.5 pr-11 py-2.5 text-sm font-mono text-white focus:outline-none focus:border-cyan-400"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-300"
                aria-label="Toggle master password visibility"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>

            {/* Live Entropy & Post-Quantum Meter */}
            {mode === "create" && entropy && (
              <div className="space-y-1 pt-0.5">
                <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${entropyBarColor}`}
                    style={{ width: `${entropy.score}%` }}
                  />
                </div>
                <div className="flex items-center justify-between gap-2 text-[10px] sm:text-[11px] font-mono">
                  <span className="text-slate-300 truncate">{entropy.strength}</span>
                  <span className="text-slate-400 whitespace-nowrap">
                    {entropy.entropy_bits}b ·{" "}
                    <span className="text-cyan-300">{entropy.post_quantum_bits}b PQ</span>
                  </span>
                </div>
              </div>
            )}

            {/* Inline KeePassDX-style Generator */}
            {mode === "create" && showMasterGen && (
              <div className="rounded-xl bg-[#07090F]/90 border cyber-accent-border p-3.5">
                <GeneratorPanel
                  onCopy={handleCopyGenerated}
                  onApply={(pw) => {
                    setMasterPassword(pw);
                    setConfirmPassword(pw);
                    setShowPassword(true);
                    setShowMasterGen(false);
                    setInfo("Master Password generated & applied — save it safely offline!");
                  }}
                />
              </div>
            )}
          </div>

          {mode === "create" && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Confirm Master Password
              </label>
              <input
                type={showPassword ? "text" : "password"}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Repeat master password..."
                autoComplete="off"
                className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 px-3.5 py-2.5 text-sm font-mono text-white focus:outline-none focus:border-cyan-400"
              />
            </div>
          )}

          {/* Optional Keyfile v2.0 XML */}
          <div>
            <div className="flex items-center justify-between gap-2 mb-1.5 flex-wrap">
              <label className="text-xs font-medium text-slate-300">
                Keyfile v2.0 XML <span className="text-slate-500">(Optional)</span>
              </label>
              <button
                type="button"
                onClick={handleGenerateKeyfile}
                className="text-[11px] font-medium text-violet-300 hover:text-violet-200 flex items-center gap-1 whitespace-nowrap"
              >
                <Sparkles className="w-3.5 h-3.5" />
                Generate Keyfile
              </button>
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={keyfilePath}
                onChange={(e) => setKeyfilePath(e.target.value)}
                placeholder="Optional .keyx / .xml keyfile"
                className="flex-1 min-w-0 rounded-xl bg-[#07090F] border border-slate-700/80 px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-violet-400"
              />
              <button
                type="button"
                onClick={handleBrowseKeyfile}
                className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 shrink-0 transition"
              >
                <FileKey2 className="w-4 h-4 text-violet-400" />
                Select
              </button>
            </div>
          </div>

          {/* KDF & Cipher Configuration (Create mode) — clean aligned mobile grid */}
          {mode === "create" && (
            <div className="rounded-xl bg-[#07090F]/85 border border-slate-800 p-3.5 space-y-3">
              <div className="text-[11px] font-semibold uppercase tracking-wider cyber-accent-text">
                Cryptographic Parameters (KDBX 4)
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Outer Cipher</label>
                  <select
                    value={cipher}
                    onChange={(e) => setCipher(e.target.value as CipherAlgorithm)}
                    className="w-full rounded-lg bg-[#0D111A] border border-slate-700 px-2.5 py-2 text-xs text-white"
                  >
                    <option value="ChaCha20">ChaCha20 (256-bit, Recommended)</option>
                    <option value="Aes256Cbc">AES-256-CBC (256-bit)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">KDF Algorithm</label>
                  <select
                    value={kdfAlgorithm}
                    onChange={(e) => setKdfAlgorithm(e.target.value as KdfAlgorithm)}
                    className="w-full rounded-lg bg-[#0D111A] border border-slate-700 px-2.5 py-2 text-xs text-white"
                  >
                    <option value="Argon2id">Argon2id v0x13 (Recommended)</option>
                    <option value="Argon2d">Argon2d v0x13</option>
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-2">
                <div>
                  <label className="block text-[10px] text-slate-400 mb-1 whitespace-nowrap">
                    MiB (≥64)
                  </label>
                  <input
                    type="number"
                    min={64}
                    max={2048}
                    value={memoryMib}
                    onChange={(e) => setMemoryMib(Number(e.target.value))}
                    className="w-full rounded-lg bg-[#0D111A] border border-slate-700 px-2.5 py-1.5 text-xs font-mono text-white"
                  />
                </div>
                <div>
                  <label className="block text-[10px] text-slate-400 mb-1 whitespace-nowrap">
                    Rounds (≥3)
                  </label>
                  <input
                    type="number"
                    min={3}
                    max={100}
                    value={iterations}
                    onChange={(e) => setIterations(Number(e.target.value))}
                    className="w-full rounded-lg bg-[#0D111A] border border-slate-700 px-2.5 py-1.5 text-xs font-mono text-white"
                  />
                </div>
                <div>
                  <label className="block text-[10px] text-slate-400 mb-1 whitespace-nowrap">
                    Lanes (≥1)
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={16}
                    value={parallelism}
                    onChange={(e) => setParallelism(Number(e.target.value))}
                    className="w-full rounded-lg bg-[#0D111A] border border-slate-700 px-2.5 py-1.5 text-xs font-mono text-white"
                  />
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="rounded-xl bg-rose-500/10 border border-rose-500/40 px-3.5 py-2.5 text-xs text-rose-200 break-words">
              {error}
            </div>
          )}
          {info && (
            <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/40 px-3.5 py-2.5 text-xs text-emerald-200 break-words">
              {info}
            </div>
          )}

          {mode === "open" && hasBioSlot && (
            <button
              type="button"
              disabled={loading}
              onClick={handleBiometricUnlock}
              className="w-full py-3 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-400/50 text-emerald-200 font-semibold text-sm tracking-wide flex items-center justify-center gap-2 transition"
            >
              <Fingerprint className="w-4 h-4 text-emerald-300" />
              {bioAvailable
                ? "Unlock Vault with Fingerprint / Face ID"
                : "Unlock Vault with Sealed Keyslot"}
            </button>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 rounded-xl cyber-btn-primary disabled:opacity-50 font-bold text-sm tracking-wide transition"
          >
            {loading
              ? "Deriving Argon2 Key..."
              : mode === "open"
              ? "Decrypt & Unlock Vault"
              : "Initialize Encrypted KDBX 4 Vault"}
          </button>
        </form>

        {/* Honest Pre-Audit Disclaimer */}
        <div className="pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 leading-relaxed flex items-start gap-2">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
          <span>
            <strong className="text-slate-300">Pre-Audit Software:</strong> Pure Rust (<code className="text-cyan-300">#![forbid(unsafe_code)]</code>), zero network access, KDBX 4 + NIST FIPS 203 ML-KEM-1024. Always keep offline backups of your <code className="text-slate-300">.kdbx</code> file.
          </span>
        </div>
      </div>

      <FolderPickerModal
        open={showFolderModal}
        defaultFileName={`${
          databaseName
            .trim()
            .replace(/[^a-zA-Z0-9_-]+/g, "_")
            .replace(/^_+|_+$/g, "") || "CipherPass_Vault"
        }.kdbx`}
        onSelectFullPath={(fullPath) => {
          setVaultPath(fullPath);
          setInfo(`Vault will be saved to: ${fullPath}`);
        }}
        onClose={() => setShowFolderModal(false)}
      />
    </div>
  );
};
