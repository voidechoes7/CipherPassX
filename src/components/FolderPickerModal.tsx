import React, { useCallback, useEffect, useState } from "react";
import {
  ArrowUp,
  Check,
  Folder,
  FolderOpen,
  FolderPlus,
  HardDrive,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";
import {
  hasAndroidAllFilesAccess,
  hasAndroidStorageBridge,
  isAndroidPlatform,
  onAndroidStoragePermissionChanged,
  pickFolder,
  pickNativeAndroidFolder,
  pickSaveKdbxFile,
  requestAndroidAllFilesAccess,
  vaultApi,
} from "../api/vaultApi";
import type { FolderListing, StorageRoot } from "../types";

interface Props {
  open: boolean;
  defaultFileName: string;
  title?: string;
  requiredExtension?: string;
  onSelectFullPath: (fullPath: string) => void;
  onClose: () => void;
}

export const FolderPickerModal: React.FC<Props> = ({
  open,
  defaultFileName,
  title = "Choose Folder for Vault",
  requiredExtension = ".kdbx",
  onSelectFullPath,
  onClose,
}) => {
  const isAndroid = isAndroidPlatform();
  const [roots, setRoots] = useState<StorageRoot[]>([]);
  const [listing, setListing] = useState<FolderListing | null>(null);
  const [newFolderName, setNewFolderName] = useState("");
  const [showNewFolder, setShowNewFolder] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [allFilesGranted, setAllFilesGranted] = useState<boolean>(!isAndroid);
  const [pickingNative, setPickingNative] = useState(false);

  const loadFolder = useCallback(async (dirPath: string) => {
    setActionError(null);
    try {
      const res = await vaultApi.listDirectoryFolders(dirPath);
      setListing(res);
    } catch (err) {
      setActionError(String(err));
    }
  }, []);

  const refreshRootsAndFolder = useCallback(
    async (preferredPath?: string) => {
      setActionError(null);
      try {
        const list = await vaultApi.getStorageRoots();
        setRoots(list);

        if (isAndroid) {
          const internalRoot = list.find((r) => r.path === "/storage/emulated/0");
          const granted =
            hasAndroidAllFilesAccess() || Boolean(internalRoot?.writable);
          setAllFilesGranted(granted);
        }

        const targetPath =
          preferredPath ||
          (isAndroid
            ? list.find((r) => r.path === "/storage/emulated/0")?.path ||
              list[0]?.path
            : list[0]?.path);
        if (targetPath) {
          await loadFolder(targetPath);
        }
      } catch (e) {
        setActionError(String(e));
      }
    },
    [isAndroid, loadFolder]
  );

  useEffect(() => {
    if (!open) return;
    setShowNewFolder(false);
    setNewFolderName("");
    setPickingNative(false);
    refreshRootsAndFolder();
  }, [open, refreshRootsAndFolder]);

  useEffect(() => {
    if (!open || !isAndroid) return;
    return onAndroidStoragePermissionChanged((granted) => {
      setAllFilesGranted(granted);
      refreshRootsAndFolder(listing?.current_path || "/storage/emulated/0");
    });
  }, [open, isAndroid, listing?.current_path, refreshRootsAndFolder]);

  if (!open) return null;

  const cleanFileName =
    defaultFileName.trim().toLowerCase().endsWith(requiredExtension.toLowerCase())
      ? defaultFileName.trim()
      : `${defaultFileName.trim() || "CipherPass_Vault"}${requiredExtension}`;

  const joinPath = (dir: string, child: string) => {
    const sep = dir.includes("\\") ? "\\" : "/";
    return `${dir.replace(/[\\/]+$/, "")}${sep}${child}`;
  };

  const handleCreateFolder = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!listing || !newFolderName.trim()) return;
    setActionError(null);
    try {
      const created = await vaultApi.createDirectory(
        listing.current_path,
        newFolderName.trim()
      );
      setNewFolderName("");
      setShowNewFolder(false);
      await loadFolder(created);
    } catch (err) {
      setActionError(String(err));
    }
  };

  const handleGrantAllFilesAccess = () => {
    setActionError(null);
    const opened = requestAndroidAllFilesAccess();
    if (!opened) {
      setActionError(
        "Open Android Settings → Apps → CipherPass → Special app access → All files access, then tap Refresh."
      );
    }
  };

  const handleNativeFolderPicker = async () => {
    setActionError(null);
    setPickingNative(true);
    try {
      if (isAndroid && hasAndroidStorageBridge()) {
        const res = await pickNativeAndroidFolder(cleanFileName);
        if (res.path) {
          onSelectFullPath(res.path);
          onClose();
          return;
        }
        if (res.error) {
          setActionError(res.error);
        }
      } else if (!isAndroid) {
        const folder = await pickFolder();
        if (folder) {
          onSelectFullPath(joinPath(folder, cleanFileName));
          onClose();
        }
      } else {
        const picked = await pickSaveKdbxFile(cleanFileName);
        if (picked) {
          onSelectFullPath(picked);
          onClose();
        }
      }
    } finally {
      setPickingNative(false);
    }
  };

  const handleSystemSaveAs = async () => {
    setActionError(null);
    const picked = await pickSaveKdbxFile(cleanFileName);
    if (picked) {
      onSelectFullPath(picked);
      onClose();
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-3 sm:p-5">
      <div className="w-full max-w-lg max-h-[88dvh] cyber-panel rounded-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between gap-2 bg-[#0D111A]">
          <div className="flex items-center gap-2 min-w-0">
            <FolderOpen className="w-4 h-4 cyber-accent-text shrink-0" />
            <h3 className="text-sm font-bold text-white truncate">
              {title}
            </h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
            aria-label="Close folder picker"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Storage Roots Chips */}
        <div className="px-4 py-2.5 border-b border-slate-800/80 bg-[#0A0E16] flex gap-1.5 overflow-x-auto">
          {roots.map((r) => {
            const active = listing?.current_path === r.path;
            return (
              <button
                key={r.path}
                type="button"
                onClick={() => loadFolder(r.path)}
                className={`px-2.5 py-1.5 rounded-lg text-[11px] font-medium whitespace-nowrap border flex items-center gap-1.5 shrink-0 transition ${
                  active
                    ? "bg-cyan-500/15 border-cyan-400/50 text-cyan-200"
                    : "bg-[#07090F] border-slate-800 text-slate-300 hover:border-slate-700"
                }`}
              >
                <HardDrive className="w-3 h-3 shrink-0" />
                <span>{r.label}</span>
              </button>
            );
          })}
        </div>

        {/* Android All Files Access (MANAGE_EXTERNAL_STORAGE) Banner */}
        {isAndroid && !allFilesGranted && (
          <div className="px-4 py-2.5 border-b border-amber-500/30 bg-amber-500/10 flex flex-col gap-2">
            <div className="flex items-start gap-2 text-[11px] text-amber-100 leading-snug">
              <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <span>
                Grant Android <strong className="text-white">All files access</strong> to
                browse &amp; save in any folder under{" "}
                <code className="text-amber-300">/storage/emulated/0</code>.
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleGrantAllFilesAccess}
                className="flex-1 py-1.5 px-3 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-400/50 text-amber-100 text-[11px] font-semibold flex items-center justify-center gap-1.5 transition"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-amber-300" />
                Grant All Files Access
              </button>
              <button
                type="button"
                onClick={() =>
                  refreshRootsAndFolder(listing?.current_path || "/storage/emulated/0")
                }
                className="py-1.5 px-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-[11px] font-medium flex items-center gap-1 transition"
                title="Refresh permission status"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Refresh
              </button>
            </div>
          </div>
        )}

        {/* Current Path Bar + Actions */}
        {listing && (
          <div className="px-4 py-2.5 border-b border-slate-800/80 flex items-center justify-between gap-2 bg-[#07090F]">
            <div className="flex items-center gap-1.5 min-w-0">
              {listing.parent_path && (
                <button
                  type="button"
                  onClick={() => loadFolder(listing.parent_path!)}
                  className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 shrink-0"
                  title="Parent folder"
                >
                  <ArrowUp className="w-3.5 h-3.5" />
                </button>
              )}
              <span className="text-[11px] font-mono text-slate-300 truncate">
                {listing.current_path}
              </span>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              <span
                className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${
                  listing.writable
                    ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
                    : "bg-amber-500/10 text-amber-300 border-amber-500/30"
                }`}
              >
                {listing.writable ? "WRITABLE" : "LOCKED"}
              </span>
              {listing.writable && (
                <button
                  type="button"
                  onClick={() => setShowNewFolder(!showNewFolder)}
                  className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300"
                  title="Create New Folder"
                >
                  <FolderPlus className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        )}

        {/* New Folder Inline Form */}
        {showNewFolder && (
          <form
            onSubmit={handleCreateFolder}
            className="px-4 py-2.5 border-b border-slate-800 bg-[#0D111A] flex gap-2"
          >
            <input
              type="text"
              value={newFolderName}
              onChange={(e) => setNewFolderName(e.target.value)}
              placeholder="New folder name (e.g. CipherPass)..."
              autoFocus
              className="flex-1 min-w-0 rounded-lg bg-[#07090F] border border-slate-700 px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-400"
            />
            <button
              type="submit"
              className="px-3 py-1.5 rounded-lg cyber-btn-primary text-xs font-bold shrink-0"
            >
              Create
            </button>
          </form>
        )}

        {/* Subfolders List */}
        <div className="flex-1 overflow-y-auto p-3 space-y-1.5 min-h-[180px]">
          {(actionError || listing?.error) && (
            <div className="rounded-xl bg-amber-500/10 border border-amber-500/35 p-3 text-[11px] text-amber-200 flex items-start gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <span>{actionError || listing?.error}</span>
            </div>
          )}

          {listing && listing.folders.length === 0 && !listing.error && (
            <div className="py-8 text-center text-xs text-slate-500">
              No subfolders here — tap <strong className="text-slate-300">Save Here</strong> or create a subfolder above.
            </div>
          )}

          {listing?.folders.map((name) => (
            <button
              key={name}
              type="button"
              onClick={() => loadFolder(joinPath(listing.current_path, name))}
              className="w-full text-left px-3 py-2.5 rounded-xl bg-[#07090F]/80 hover:bg-slate-800/70 border border-slate-800/80 flex items-center gap-2.5 transition"
            >
              <Folder className="w-4 h-4 text-cyan-400 shrink-0" />
              <span className="text-xs font-medium text-slate-100 truncate">{name}</span>
            </button>
          ))}
        </div>

        {/* Footer Actions */}
        <div className="px-4 py-3 border-t border-slate-800 bg-[#0D111A] space-y-2">
          <button
            type="button"
            disabled={!listing || !listing.writable}
            onClick={() => {
              if (!listing) return;
              onSelectFullPath(joinPath(listing.current_path, cleanFileName));
              onClose();
            }}
            className="w-full py-2.5 px-3 rounded-xl cyber-btn-primary disabled:opacity-40 text-xs font-bold flex items-center justify-center gap-1.5 transition"
          >
            <Check className="w-4 h-4" />
            Save Here ({cleanFileName})
          </button>
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              disabled={pickingNative}
              onClick={handleNativeFolderPicker}
              className="py-2 px-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-[11px] font-medium text-cyan-200 transition disabled:opacity-50"
            >
              {pickingNative ? "Opening..." : "Native Folder Picker"}
            </button>
            <button
              type="button"
              onClick={handleSystemSaveAs}
              className="py-2 px-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-[11px] font-medium text-slate-200 transition"
            >
              System Save As (SAF)
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

