import React, { useState } from "react";
import {
  AlertTriangle,
  Eye,
  EyeOff,
  FileKey2,
  FolderOpen,
  Lock,
  PlusCircle,
  Shield,
  Sparkles,
  WifiOff,
} from "lucide-react";
import {
  isTauriRuntime,
  pickOpenKdbxFile,
  pickOpenKeyfile,
  pickSaveKdbxFile,
  pickSaveKeyfile,
  vaultApi,
} from "../api/vaultApi";
import type { CipherAlgorithm, KdfAlgorithm, VaultStatus } from "../types";

interface Props {
  onUnlocked: (status: VaultStatus) => void;
}

export const UnlockScreen: React.FC<Props> = ({ onUnlocked }) => {
  const [mode, setMode] = useState<"open" | "create">("open");
  const [vaultPath, setVaultPath] = useState("");
  const [databaseName, setDatabaseName] = useState("CipherPass Vault");
  const [masterPassword, setMasterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
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

  const handleBrowseVault = async () => {
    setError(null);
    const picked =
      mode === "open"
        ? await pickOpenKdbxFile()
        : await pickSaveKdbxFile(`${databaseName.replace(/\s+/g, "_") || "CipherPass"}.kdbx`);
    if (picked) setVaultPath(picked);
  };

  const handleBrowseKeyfile = async () => {
    setError(null);
    const picked = await pickOpenKeyfile();
    if (picked) setKeyfilePath(picked);
  };

  const handleGenerateKeyfile = async () => {
    setError(null);
    setInfo(null);
    const dest = await pickSaveKeyfile("CipherPass_Keyfile_v2.keyx");
    if (!dest) return;
    try {
      await vaultApi.generateKeyfileToPath(dest);
      setKeyfilePath(dest);
      setInfo("Generated 256-bit Keyfile v2.0 XML (KeePassXC / KeePassDX compatible). Keep a secure offline backup!");
    } catch (e) {
      setError(String(e));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setInfo(null);

    if (!vaultPath.trim()) {
      setError("Please select or enter a .kdbx vault file path.");
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
              path: vaultPath.trim(),
              master_password: masterPassword || null,
              keyfile_path: keyfilePath.trim() || null,
            })
          : await vaultApi.createVault({
              path: vaultPath.trim(),
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

  return (
    <div className="min-h-full flex flex-col items-center justify-center p-4 sm:p-6 bg-[radial-gradient(ellipse_at_top,_rgba(0,240,255,0.08),_transparent_60%),radial-gradient(ellipse_at_bottom_right,_rgba(139,92,246,0.08),_transparent_55%)]">
      <div className="w-full max-w-xl cyber-panel rounded-2xl p-6 sm:p-8 space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center cyber-glow">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                CipherPass
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-400/30">
                  KDBX 4 / PQ-256
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                KeePassXC &amp; KeePassDX Interoperable · Rust Pure Core
              </p>
            </div>
          </div>

          <div className="flex items-center gap-1.5 text-[11px] font-mono px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 shrink-0">
            <WifiOff className="w-3.5 h-3.5" />
            100% OFFLINE
          </div>
        </div>

        {/* Mode Tabs */}
        <div className="grid grid-cols-2 gap-2 p-1 rounded-xl bg-[#07090F] border border-slate-800">
          <button
            type="button"
            onClick={() => {
              setMode("open");
              setError(null);
            }}
            className={`flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition ${
              mode === "open"
                ? "bg-cyan-500/15 text-cyan-300 border border-cyan-400/30"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Lock className="w-4 h-4" />
            Unlock Vault (.kdbx)
          </button>
          <button
            type="button"
            onClick={() => {
              setMode("create");
              setError(null);
            }}
            className={`flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition ${
              mode === "create"
                ? "bg-violet-500/15 text-violet-300 border border-violet-400/30"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <PlusCircle className="w-4 h-4" />
            Create New Vault
          </button>
        </div>

        {!isTauriRuntime() && (
          <div className="rounded-xl bg-amber-500/10 border border-amber-500/30 p-3 text-xs text-amber-200 flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-amber-400" />
            <span>
              Browser preview detected. Native KDBX 4 encryption, Argon2id, and atomic file I/O run inside the Tauri 2 desktop/mobile binary.
            </span>
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
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              KDBX 4 Database Path
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={vaultPath}
                onChange={(e) => setVaultPath(e.target.value)}
                placeholder="/path/to/vault.kdbx"
                className="flex-1 rounded-xl bg-[#07090F] border border-slate-700/80 px-3.5 py-2.5 text-sm font-mono text-slate-100 focus:outline-none focus:border-cyan-400"
              />
              <button
                type="button"
                onClick={handleBrowseVault}
                className="px-3.5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition"
              >
                <FolderOpen className="w-4 h-4 text-cyan-400" />
                Browse
              </button>
            </div>
          </div>

          {/* Master Password */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Master Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                value={masterPassword}
                onChange={(e) => setMasterPassword(e.target.value)}
                placeholder="Enter master password..."
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
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-medium text-slate-300">
                Keyfile v2.0 XML <span className="text-slate-500">(Optional 256-bit PQ factor)</span>
              </label>
              <button
                type="button"
                onClick={handleGenerateKeyfile}
                className="text-[11px] font-medium text-violet-300 hover:text-violet-200 flex items-center gap-1"
              >
                <Sparkles className="w-3.5 h-3.5" />
                Generate Keyfile v2.0
              </button>
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={keyfilePath}
                onChange={(e) => setKeyfilePath(e.target.value)}
                placeholder="Optional .keyx / .xml keyfile path"
                className="flex-1 rounded-xl bg-[#07090F] border border-slate-700/80 px-3.5 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-violet-400"
              />
              <button
                type="button"
                onClick={handleBrowseKeyfile}
                className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition"
              >
                <FileKey2 className="w-4 h-4 text-violet-400" />
                Select
              </button>
            </div>
          </div>

          {/* KDF & Cipher Configuration (Create mode) */}
          {mode === "create" && (
            <div className="rounded-xl bg-[#07090F]/80 border border-slate-800 p-4 space-y-3">
              <div className="text-xs font-semibold uppercase tracking-wider text-cyan-300">
                Cryptographic Parameters (KDBX 4)
              </div>
              <div className="grid grid-cols-2 gap-3">
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
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Memory (MiB, ≥64)</label>
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
                  <label className="block text-[11px] text-slate-400 mb-1">Rounds (≥3)</label>
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
                  <label className="block text-[11px] text-slate-400 mb-1">Lanes (≥1)</label>
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
            <div className="rounded-xl bg-rose-500/10 border border-rose-500/40 px-3.5 py-2.5 text-xs text-rose-200">
              {error}
            </div>
          )}
          {info && (
            <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/40 px-3.5 py-2.5 text-xs text-emerald-200">
              {info}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-violet-600 hover:from-cyan-400 hover:to-violet-500 disabled:opacity-50 text-slate-950 font-semibold text-sm tracking-wide transition shadow-lg shadow-cyan-500/20"
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
            <strong className="text-slate-300">Pre-Audit Software:</strong> CipherPass implements standard KDBX 4 cryptography in pure Rust (<code className="text-cyan-300">#![forbid(unsafe_code)]</code>) with zero network access, but has not yet undergone an independent third-party audit. Always keep offline backups of your <code className="text-slate-300">.kdbx</code> file.
          </span>
        </div>
      </div>
    </div>
  );
};
