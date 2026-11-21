import React, { useState } from "react";
import { Atom, Download, FileKey2, Lock, Save, Shield, Unlock } from "lucide-react";
import {
  pickOpenPqFile,
  pickSaveKdbxFile,
  pickSaveKeyfile,
  pickSavePqFile,
  vaultApi,
} from "../api/vaultApi";
import type { CipherAlgorithm, KdfAlgorithm, MlKem1024Keypair, VaultStatus } from "../types";

interface Props {
  status: VaultStatus;
  onStatusUpdated: (status: VaultStatus) => void;
}

export const SettingsView: React.FC<Props> = ({ status, onStatusUpdated }) => {
  const [cipher, setCipher] = useState<CipherAlgorithm>(status.cipher ?? "ChaCha20");
  const [kdfAlg, setKdfAlg] = useState<KdfAlgorithm>(status.kdf?.algorithm ?? "Argon2id");
  const [memoryMib, setMemoryMib] = useState(status.kdf?.memory_mib ?? 128);
  const [iterations, setIterations] = useState(status.kdf?.iterations ?? 4);
  const [parallelism, setParallelism] = useState(status.kdf?.parallelism ?? 4);
  const [autoLock, setAutoLock] = useState(status.auto_lock_seconds);
  const [clipClear, setClipClear] = useState(status.clipboard_clear_seconds);

  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // NIST FIPS 203 ML-KEM-1024 Post-Quantum Armor state
  const [pqKeypair, setPqKeypair] = useState<MlKem1024Keypair | null>(null);
  const [pqPubKey, setPqPubKey] = useState("");
  const [pqSecKey, setPqSecKey] = useState("");

  const handleSave = async (e: React.FormEvent) => {
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
      setMessage("Security settings saved and vault re-encrypted atomically.");
    } catch (err) {
      setError(String(err));
    } finally {
      setSaving(false);
    }
  };

  const handleExportBackup = async () => {
    setMessage(null);
    setError(null);
    const dest = await pickSaveKdbxFile("CipherPass_Backup.kdbx");
    if (!dest) return;
    try {
      await vaultApi.exportVaultBackup(dest);
      setMessage(`Atomic KDBX 4 backup exported to ${dest}`);
    } catch (err) {
      setError(String(err));
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

  return (
    <div className="p-4 sm:p-6 max-w-3xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Shield className="w-5 h-5 text-cyan-400" />
          Cryptographic &amp; Session Security
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          All changes re-encrypt the KDBX 4 file atomically (<code className="text-cyan-300">.tmp</code> + fsync + rename).
        </p>
      </div>

      {message && (
        <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/40 px-4 py-3 text-xs text-emerald-200">
          {message}
        </div>
      )}
      {error && (
        <div className="rounded-xl bg-rose-500/10 border border-rose-500/40 px-4 py-3 text-xs text-rose-200">
          {error}
        </div>
      )}

      <form onSubmit={handleSave} className="cyber-panel rounded-2xl p-5 space-y-5">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Outer Encryption Cipher</label>
            <select
              value={cipher}
              onChange={(e) => setCipher(e.target.value as CipherAlgorithm)}
              className="w-full rounded-xl bg-[#07090F] border border-slate-700 px-3 py-2 text-sm text-white"
            >
              <option value="ChaCha20">ChaCha20 (256-bit, Recommended)</option>
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
              <option value="Argon2id">Argon2id v0x13 (Hybrid, Recommended)</option>
              <option value="Argon2d">Argon2d v0x13 (GPU-resistant)</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Memory (MiB, ≥64)</label>
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
            <label className="block text-xs text-slate-400 mb-1">Iterations (≥3)</label>
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
            <label className="block text-xs text-slate-400 mb-1">Parallelism (≥1)</label>
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

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-slate-800">
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
          className="px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs flex items-center gap-2 transition"
        >
          <Save className="w-4 h-4" />
          {saving ? "Re-encrypting..." : "Apply & Save Security Settings"}
        </button>
      </form>

      {/* Backup & Keyfile Tools */}
      <div className="cyber-panel rounded-2xl p-5 space-y-3">
        <h3 className="text-sm font-semibold text-white">Offline Backup &amp; Keyfile Tools</h3>
        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            onClick={handleExportBackup}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-cyan-300 font-medium flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            Export Atomic .kdbx Backup
          </button>
          <button
            type="button"
            onClick={handleGenerateKeyfile}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-violet-300 font-medium flex items-center gap-2"
          >
            <FileKey2 className="w-4 h-4" />
            Generate New Keyfile v2.0 XML
          </button>
        </div>
      </div>

      {/* NIST FIPS 203 ML-KEM-1024 Post-Quantum Armor */}
      <div className="cyber-panel rounded-2xl p-5 space-y-4 border-violet-500/30">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Atom className="w-4 h-4 text-violet-400" />
              Post-Quantum Vault Armor (NIST FIPS 203 ML-KEM-1024)
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Wrap your standard <code className="text-cyan-300">.kdbx</code> inside an ML-KEM-1024 (Category 5) + SHA3-512 + ChaCha20-Poly1305 quantum-safe envelope (<code className="text-violet-300">.kdbx.pq</code>) for cold storage or untrusted cloud sync.
            </p>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-violet-500/15 text-violet-300 border border-violet-400/30 shrink-0">
            FIPS 203
          </span>
        </div>

        <div className="flex flex-wrap gap-2.5">
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
                setMessage(`Generated ML-KEM-1024 keypair (Fingerprint: ${kp.fingerprint}). Store your secret key offline!`);
              } catch (err) {
                setError(String(err));
              }
            }}
            className="px-3.5 py-2 rounded-xl bg-violet-500/20 hover:bg-violet-500/30 border border-violet-400/40 text-xs text-violet-200 font-medium flex items-center gap-1.5"
          >
            <Atom className="w-3.5 h-3.5" />
            Generate ML-KEM-1024 Keypair
          </button>

          <button
            type="button"
            onClick={async () => {
              setError(null);
              setMessage(null);
              if (!pqPubKey.trim()) {
                setError("Paste or generate an ML-KEM-1024 Public Key first.");
                return;
              }
              const dest = await pickSavePqFile("CipherPass_QuantumBackup.kdbx.pq");
              if (!dest) return;
              try {
                await vaultApi.exportPqArmoredVault(dest, pqPubKey.trim());
                setMessage(`Vault sealed with FIPS 203 ML-KEM-1024 to ${dest}`);
              } catch (err) {
                setError(String(err));
              }
            }}
            className="px-3.5 py-2 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-400/30 text-xs text-cyan-200 font-medium flex items-center gap-1.5"
          >
            <Lock className="w-3.5 h-3.5" />
            Seal Vault to .kdbx.pq
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
            Unseal .kdbx.pq → .kdbx
          </button>
        </div>

        {pqKeypair && (
          <div className="text-[11px] font-mono text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 rounded-lg px-3 py-2">
            Public Key SHA3-512 Fingerprint: {pqKeypair.fingerprint}
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className="block text-[11px] text-slate-400 mb-1">
              ML-KEM-1024 Public Key (Base64)
            </label>
            <textarea
              rows={2}
              value={pqPubKey}
              onChange={(e) => setPqPubKey(e.target.value)}
              placeholder="Encapsulation key..."
              className="w-full rounded-lg bg-[#07090F] border border-slate-700 px-2.5 py-1.5 text-[10px] font-mono text-cyan-200"
            />
          </div>
          <div>
            <label className="block text-[11px] text-slate-400 mb-1">
              ML-KEM-1024 Secret Key (Base64 — Keep Offline)
            </label>
            <textarea
              rows={2}
              value={pqSecKey}
              onChange={(e) => setPqSecKey(e.target.value)}
              placeholder="Decapsulation key..."
              className="w-full rounded-lg bg-[#07090F] border border-slate-700 px-2.5 py-1.5 text-[10px] font-mono text-violet-200"
            />
          </div>
        </div>
      </div>

      {/* License & Pre-audit notice */}
      <div className="rounded-xl bg-[#0D111A] border border-slate-800 p-4 text-[11px] text-slate-400 space-y-1">
        <div className="text-slate-300 font-semibold">
          CipherPass · All Rights Reserved — Private Personal Use
        </div>
        <div>
          Engine: Pure Rust (<code className="text-cyan-300">#![forbid(unsafe_code)]</code>), KDBX 4 / 4.1, zero telemetry, zero network sockets. Pre-audit software — always keep verified offline backups.
        </div>
      </div>
    </div>
  );
};
