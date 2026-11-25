import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  Copy,
  CreditCard,
  Eraser,
  Eye,
  EyeOff,
  FileText,
  Folder,
  FolderOpen,
  FolderPlus,
  KeyRound,
  Lock,
  Pencil,
  Plus,
  RotateCcw,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Star,
  Terminal,
  Trash2,
  User,
  Wand2,
  WifiOff,
  X,
} from "lucide-react";
import {
  applyScreenProtection,
  isTauriRuntime,
  loadBackgroundLockSeconds,
  loadMaskEntrySubtitles,
  loadScreenProtection,
  onAndroidAppBackgrounded,
  saveBackgroundLockSeconds,
  saveMaskEntrySubtitles,
  vaultApi,
} from "./api/vaultApi";
import { AuditView } from "./components/AuditView";
import { EntryEditor } from "./components/EntryEditor";
import { GeneratorPanel } from "./components/GeneratorPanel";
import { SettingsView } from "./components/SettingsView";
import { ThemePicker, UiStylePicker } from "./components/ThemePicker";
import { TotpBadge } from "./components/TotpBadge";
import { UnlockScreen } from "./components/UnlockScreen";
import {
  applyFontScale,
  applyTheme,
  applyUiStyle,
  loadSavedFontScale,
  loadSavedTheme,
  loadSavedUiStyle,
  type FontScaleId,
  type ThemeId,
  type UiStyleId,
} from "./themes";
import type { EntryDetail, EntrySummary, EntryType, GroupNode, VaultStatus } from "./types";

type ActiveTab = "vault" | "totp" | "generator" | "audit" | "settings";

const MOBILE_NAV_ITEMS: {
  id: ActiveTab;
  icon: React.FC<{ className?: string }>;
  label: string;
}[] = [
  { id: "vault", icon: KeyRound, label: "Vault" },
  { id: "totp", icon: ShieldCheck, label: "2FA" },
  { id: "generator", icon: Wand2, label: "Gen" },
  { id: "audit", icon: ShieldAlert, label: "Audit" },
  { id: "settings", icon: Settings, label: "Settings" },
];

function renderEntryTypeIcon(entryType: EntryType) {
  switch (entryType) {
    case "card":
      return <CreditCard className="w-3.5 h-3.5 text-amber-400 shrink-0" />;
    case "totp":
      return <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />;
    case "dev":
      return <Terminal className="w-3.5 h-3.5 text-violet-400 shrink-0" />;
    case "note":
      return <FileText className="w-3.5 h-3.5 text-slate-400 shrink-0" />;
    default:
      return <KeyRound className="w-3.5 h-3.5 cyber-accent-text shrink-0" />;
  }
}

function entryTypeLabel(entryType: EntryType): string {
  switch (entryType) {
    case "card":
      return "CARD";
    case "totp":
      return "2FA";
    case "dev":
      return "SSH/API";
    case "note":
      return "NOTE";
    default:
      return "LOGIN";
  }
}

function findGroupTrail(node: GroupNode, targetId: string): GroupNode[] | null {
  if (node.id === targetId) return [node];
  for (const sub of node.subgroups) {
    const found = findGroupTrail(sub, targetId);
    if (found) return [node, ...found];
  }
  return null;
}

function countGroupRecursive(node: GroupNode): number {
  return (
    node.entry_count +
    node.subgroups.reduce((sum, sub) => sum + countGroupRecursive(sub), 0)
  );
}

export const App: React.FC = () => {
  const [theme, setTheme] = useState<ThemeId>(() => loadSavedTheme());
  const [uiStyle, setUiStyle] = useState<UiStyleId>(() => loadSavedUiStyle());
  const [fontScale, setFontScale] = useState<FontScaleId>(() => loadSavedFontScale());
  const [maskSubtitles, setMaskSubtitles] = useState<boolean>(() => loadMaskEntrySubtitles());
  const [bgLockSeconds, setBgLockSeconds] = useState<number>(() => loadBackgroundLockSeconds());
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [groups, setGroups] = useState<GroupNode | null>(null);
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [selectedEntry, setSelectedEntry] = useState<EntryDetail | null>(null);
  const [creatingNew, setCreatingNew] = useState(false);
  const [focusTotpOnCreate, setFocusTotpOnCreate] = useState(false);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const backgroundedAtRef = useRef<number | null>(null);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    applyUiStyle(uiStyle);
  }, [uiStyle]);

  useEffect(() => {
    applyFontScale(fontScale);
  }, [fontScale]);

  useEffect(() => {
    applyScreenProtection(loadScreenProtection());
  }, []);

  const handleMaskSubtitlesChange = useCallback((masked: boolean) => {
    setMaskSubtitles(masked);
    saveMaskEntrySubtitles(masked);
  }, []);

  const handleBgLockSecondsChange = useCallback((secs: number) => {
    setBgLockSeconds(secs);
    saveBackgroundLockSeconds(secs);
  }, []);

  const [activeTab, setActiveTab] = useState<ActiveTab>("vault");
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  // Folder management state (create root/subfolder, rename, delete, mobile tree drawer)
  const [showFolderBrowserMobile, setShowFolderBrowserMobile] = useState(false);
  const [newGroupName, setNewGroupName] = useState("");
  const [newGroupParentId, setNewGroupParentId] = useState<string | null>(null);
  const [showNewGroupInput, setShowNewGroupInput] = useState(false);
  const [renamingGroupId, setRenamingGroupId] = useState<string | null>(null);
  const [renameGroupText, setRenameGroupText] = useState("");
  const [confirmDeleteGroupId, setConfirmDeleteGroupId] = useState<string | null>(null);

  // Liquid Glass interactive sliding bottom dock state
  const dockRef = useRef<HTMLDivElement | null>(null);
  const [dockDragging, setDockDragging] = useState(false);
  const [dockDragPercent, setDockDragPercent] = useState<number | null>(null);
  const [dockPreviewIdx, setDockPreviewIdx] = useState<number | null>(null);
  const dockStartXRef = useRef<number>(0);
  const dockMovedRef = useRef<boolean>(false);

  const [toast, setToast] = useState<string | null>(null);

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    setTimeout(() => {
      setToast((curr) => (curr === msg ? null : curr));
    }, 3500);
  }, []);

  const refreshVaultData = useCallback(async () => {
    try {
      const [g, list, s] = await Promise.all([
        vaultApi.listGroups(),
        vaultApi.listEntries({
          groupId: activeTab === "totp" ? null : selectedGroupId,
          query: searchQuery,
          favoritesOnly: activeTab === "totp" ? false : favoritesOnly,
          totpOnly: activeTab === "totp",
        }),
        vaultApi.getStatus(),
      ]);
      setGroups(g);
      setEntries(list);
      setStatus(s);
    } catch {
      // Locked or unavailable
    }
  }, [activeTab, selectedGroupId, searchQuery, favoritesOnly]);

  const handleLock = useCallback(async () => {
    try {
      const s = await vaultApi.lockVault();
      setStatus(s);
    } catch {
      setStatus((prev) => (prev ? { ...prev, unlocked: false } : prev));
    } finally {
      setSelectedEntry(null);
      setCreatingNew(false);
      setFocusTotpOnCreate(false);
      setSearchQuery("");
      setEntries([]);
      setGroups(null);
    }
  }, []);

  useEffect(() => {
    vaultApi
      .getStatus()
      .then((s) => setStatus(s))
      .catch(() =>
        setStatus({
          unlocked: false,
          path: null,
          database_name: null,
          database_description: null,
          cipher: null,
          inner_cipher: null,
          kdbx_version: null,
          kdf: null,
          has_master_password: false,
          has_keyfile: false,
          keyfile_path: null,
          compression: true,
          pq_armor_available: true,
          entry_count: 0,
          recycle_bin_id: null,
          dirty: false,
          auto_lock_seconds: 300,
          clipboard_clear_seconds: 30,
        })
      );

    let unlistenLock: (() => void) | undefined;
    let unlistenClip: (() => void) | undefined;

    vaultApi.onAutoLocked(() => {
      setStatus((prev) => (prev ? { ...prev, unlocked: false } : prev));
      setSelectedEntry(null);
      setCreatingNew(false);
      setFocusTotpOnCreate(false);
      setSearchQuery("");
      setEntries([]);
      setGroups(null);
      showToast("Vault auto-locked & secrets zeroized in memory.");
    }).then((fn) => (unlistenLock = fn));

    vaultApi.onClipboardCleared(() => {
      showToast("Clipboard cleared automatically.");
    }).then((fn) => (unlistenClip = fn));

    return () => {
      unlistenLock?.();
      unlistenClip?.();
    };
  }, [showToast]);

  useEffect(() => {
    if (status?.unlocked) {
      refreshVaultData();
    }
  }, [status?.unlocked, refreshVaultData]);

  // Background / Minimize Auto-Lock (works on Android onPause + Desktop/Web visibilitychange)
  useEffect(() => {
    if (!status?.unlocked || bgLockSeconds <= 0) {
      backgroundedAtRef.current = null;
      return;
    }

    let bgTimer: number | null = null;
    const clearBgTimer = () => {
      if (bgTimer !== null) {
        window.clearTimeout(bgTimer);
        bgTimer = null;
      }
    };

    const handleBackground = () => {
      clearBgTimer();
      if (bgLockSeconds === 1) {
        void handleLock();
      } else {
        backgroundedAtRef.current = Date.now();
        bgTimer = window.setTimeout(() => {
          bgTimer = null;
          void handleLock();
        }, bgLockSeconds * 1000);
      }
    };

    const handleForeground = () => {
      clearBgTimer();
      const hiddenAt = backgroundedAtRef.current;
      backgroundedAtRef.current = null;
      if (hiddenAt !== null) {
        const elapsedSec = (Date.now() - hiddenAt) / 1000;
        if (elapsedSec >= bgLockSeconds) {
          void handleLock();
        }
      }
    };

    const onVisibility = () => {
      if (document.hidden) {
        handleBackground();
      } else {
        handleForeground();
      }
    };

    document.addEventListener("visibilitychange", onVisibility);
    const unsubAndroidBg = onAndroidAppBackgrounded(handleBackground);
    return () => {
      clearBgTimer();
      document.removeEventListener("visibilitychange", onVisibility);
      unsubAndroidBg();
    };
  }, [status?.unlocked, bgLockSeconds, handleLock]);

  // Desktop Keyboard Shortcuts: Ctrl/Cmd+K (search), Ctrl/Cmd+N (new), Ctrl/Cmd+L (lock), Escape
  useEffect(() => {
    if (!status?.unlocked) return;
    const onKeyDown = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      const key = e.key.toLowerCase();
      if (mod && key === "k") {
        e.preventDefault();
        setActiveTab("vault");
        setTimeout(() => searchInputRef.current?.focus(), 20);
      } else if (mod && key === "n") {
        e.preventDefault();
        setActiveTab("vault");
        setSelectedEntry(null);
        setCreatingNew(true);
        setFocusTotpOnCreate(false);
      } else if (mod && key === "l") {
        e.preventDefault();
        void handleLock();
      } else if (e.key === "Escape") {
        if (searchQuery) {
          setSearchQuery("");
        } else if (showFolderBrowserMobile) {
          setShowFolderBrowserMobile(false);
        }
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [status?.unlocked, handleLock, searchQuery, showFolderBrowserMobile]);

  const activeGroupTrail = useMemo(() => {
    if (!groups || !selectedGroupId) return null;
    return findGroupTrail(groups, selectedGroupId);
  }, [groups, selectedGroupId]);

  const activeFolderNode =
    activeGroupTrail && activeGroupTrail.length > 0
      ? activeGroupTrail[activeGroupTrail.length - 1]
      : null;

  const handleSelectEntry = async (id: string) => {
    try {
      const detail = await vaultApi.getEntry(id);
      setSelectedEntry(detail);
      setCreatingNew(false);
      if (activeTab !== "vault" && activeTab !== "totp") {
        setActiveTab("vault");
      }
    } catch (e) {
      showToast(String(e));
    }
  };

  const handleCopy = async (secret: string, label: string) => {
    try {
      const secs = await vaultApi.copySecretWithAutoClear(secret);
      showToast(`${label} copied — clipboard auto-clears in ${secs}s`);
    } catch {
      if (isTauriRuntime()) {
        // Never fall back to navigator.clipboard inside Tauri, which would bypass auto-clear
        showToast("Clipboard copy failed (auto-clear protection active)");
        return;
      }
      try {
        await navigator.clipboard.writeText(secret);
        showToast(`${label} copied`);
      } catch {
        showToast("Clipboard copy failed");
      }
    }
  };

  const openCreateFolderForm = (parentId: string | null) => {
    setNewGroupParentId(parentId);
    setNewGroupName("");
    setShowNewGroupInput(true);
    setRenamingGroupId(null);
    setConfirmDeleteGroupId(null);
  };

  const handleCreateGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!groups || !newGroupName.trim()) return;
    const parentTarget = newGroupParentId ?? selectedGroupId ?? groups.id;
    try {
      const created = await vaultApi.createGroup(parentTarget, newGroupName.trim());
      setNewGroupName("");
      setShowNewGroupInput(false);
      setNewGroupParentId(null);
      setSelectedGroupId(created.id);
      setFavoritesOnly(false);
      await refreshVaultData();
      showToast(`Folder "${created.name}" created & saved.`);
    } catch (err) {
      showToast(String(err));
    }
  };

  const handleRenameGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!renamingGroupId || !renameGroupText.trim()) return;
    try {
      const updated = await vaultApi.renameGroup(renamingGroupId, renameGroupText.trim());
      setRenamingGroupId(null);
      setRenameGroupText("");
      await refreshVaultData();
      showToast(`Folder renamed to "${updated.name}".`);
    } catch (err) {
      showToast(String(err));
    }
  };

  const handleDeleteGroup = async (gid: string) => {
    try {
      await vaultApi.deleteGroup(gid);
      if (selectedGroupId === gid) {
        setSelectedGroupId(null);
      }
      setConfirmDeleteGroupId(null);
      await refreshVaultData();
      showToast("Folder deleted.");
    } catch (err) {
      showToast(String(err));
    }
  };

  const switchMobileTab = (tabId: ActiveTab) => {
    setActiveTab(tabId);
    setSelectedEntry(null);
    setCreatingNew(false);
    setFocusTotpOnCreate(false);
  };

  // Liquid Glass touch/pointer horizontal sliding dock handlers
  const updateDockPosition = (clientX: number) => {
    const el = dockRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const count = MOBILE_NAV_ITEMS.length;
    const rel = Math.max(0, Math.min(rect.width - 1, clientX - rect.left));
    const idx = Math.min(count - 1, Math.floor((rel / rect.width) * count));
    const clampedPct = Math.max(0, Math.min((count - 1) * 100, (rel / rect.width) * count * 100 - 50));
    setDockDragPercent(clampedPct);
    setDockPreviewIdx(idx);
  };

  const handleDockTouchStart = (e: React.TouchEvent<HTMLDivElement>) => {
    if (e.touches.length === 0) return;
    dockStartXRef.current = e.touches[0].clientX;
    dockMovedRef.current = false;
    setDockDragging(true);
  };

  const handleDockTouchMove = (e: React.TouchEvent<HTMLDivElement>) => {
    if (!dockDragging || e.touches.length === 0) return;
    const x = e.touches[0].clientX;
    if (Math.abs(x - dockStartXRef.current) > 8) {
      dockMovedRef.current = true;
    }
    if (dockMovedRef.current) {
      updateDockPosition(x);
    }
  };

  const handleDockTouchEnd = () => {
    if (dockMovedRef.current && dockPreviewIdx !== null) {
      const target = MOBILE_NAV_ITEMS[dockPreviewIdx];
      if (target) switchMobileTab(target.id);
    }
    setDockDragging(false);
    setDockDragPercent(null);
    setDockPreviewIdx(null);
    dockMovedRef.current = false;
  };

  if (!status || !status.unlocked) {
    return (
      <UnlockScreen
        theme={theme}
        uiStyle={uiStyle}
        onThemeChange={setTheme}
        onUiStyleChange={setUiStyle}
        onUnlocked={(s) => {
          setStatus(s);
          setActiveTab("vault");
        }}
      />
    );
  }

  const isViewingRecycleBin = Boolean(
    status.recycle_bin_id && selectedGroupId === status.recycle_bin_id
  );

  const defaultGroupId =
    (selectedGroupId && selectedGroupId !== status.recycle_bin_id ? selectedGroupId : null) ??
    groups?.subgroups.find((g) => g.id !== status.recycle_bin_id)?.id ??
    groups?.id ??
    "";

  const showingEditorMobile = Boolean(selectedEntry || creatingNew);
  const activeTabIdx = Math.max(
    0,
    MOBILE_NAV_ITEMS.findIndex((item) => item.id === activeTab)
  );
  const sliderTransformPercent =
    dockDragPercent !== null ? dockDragPercent : activeTabIdx * 100;

  const renderGroupTree = (node: GroupNode, depth = 0, onSelectExtra?: () => void) => {
    const isRoot = depth === 0;
    const isRecycleBin = Boolean(status.recycle_bin_id && node.id === status.recycle_bin_id);
    const isSelected =
      activeTab === "vault" &&
      !favoritesOnly &&
      ((isRoot && selectedGroupId === null) || selectedGroupId === node.id);
    const totalCount = isRoot
      ? status.entry_count
      : countGroupRecursive(node);

    return (
      <div key={node.id} className="space-y-0.5">
        <div
          style={{ paddingLeft: `${8 + depth * 12}px` }}
          className={`group flex items-center justify-between gap-1 pr-1.5 py-1.5 rounded-lg text-xs transition ${
            isSelected
              ? isRecycleBin
                ? "bg-rose-500/15 text-rose-300 border border-rose-400/30"
                : "bg-cyan-500/15 text-cyan-300 border border-cyan-400/25"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
          }`}
        >
          <button
            type="button"
            onClick={() => {
              setActiveTab("vault");
              setFavoritesOnly(false);
              setSelectedGroupId(isRoot ? null : node.id);
              setConfirmDeleteGroupId(null);
              onSelectExtra?.();
            }}
            className="flex items-center gap-2 min-w-0 flex-1 text-left"
          >
            {isRecycleBin ? (
              <Trash2 className="w-3.5 h-3.5 shrink-0 text-rose-400" />
            ) : isSelected ? (
              <FolderOpen className="w-3.5 h-3.5 shrink-0 cyber-accent-text" />
            ) : (
              <Folder className="w-3.5 h-3.5 shrink-0 cyber-accent-text opacity-75" />
            )}
            <span className="truncate font-medium">
              {isRoot ? "All Entries" : node.name}
            </span>
          </button>

          <div className="flex items-center gap-1 shrink-0">
            {totalCount > 0 && (
              <span className="text-[10px] font-mono text-slate-500 px-1">
                {totalCount}
              </span>
            )}
            {!isRecycleBin && (
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  openCreateFolderForm(node.id);
                }}
                className="p-1 rounded hover:bg-slate-700/70 text-slate-400 hover:text-cyan-300 opacity-75 group-hover:opacity-100"
                title={`Add subfolder inside ${isRoot ? "Vault Root" : node.name}`}
              >
                <FolderPlus className="w-3 h-3" />
              </button>
            )}
            {!isRoot && !isRecycleBin && (
              <>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setRenamingGroupId(node.id);
                    setRenameGroupText(node.name);
                    setShowNewGroupInput(false);
                    setConfirmDeleteGroupId(null);
                  }}
                  className="p-1 rounded hover:bg-slate-700/70 text-slate-400 hover:text-amber-300 opacity-75 group-hover:opacity-100"
                  title="Rename folder"
                >
                  <Pencil className="w-3 h-3" />
                </button>
                {confirmDeleteGroupId === node.id ? (
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleDeleteGroup(node.id);
                    }}
                    className="px-1.5 py-0.5 rounded bg-rose-500/25 border border-rose-400/50 text-[9px] font-bold text-rose-200"
                    title="Confirm delete folder"
                  >
                    Del?
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setConfirmDeleteGroupId(node.id);
                    }}
                    className="p-1 rounded hover:bg-rose-500/20 text-slate-400 hover:text-rose-300 opacity-75 group-hover:opacity-100"
                    title="Delete folder"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                )}
              </>
            )}
          </div>
        </div>

        {renamingGroupId === node.id && (
          <form
            onSubmit={handleRenameGroup}
            style={{ paddingLeft: `${12 + depth * 12}px` }}
            className="flex gap-1 pr-1.5 py-1"
          >
            <input
              type="text"
              value={renameGroupText}
              onChange={(e) => setRenameGroupText(e.target.value)}
              autoFocus
              className="flex-1 min-w-0 rounded-lg bg-[#07090F] border border-amber-400/50 px-2 py-1 text-xs text-white"
            />
            <button
              type="submit"
              className="px-2 py-1 rounded-lg cyber-btn-primary text-[11px] font-bold"
            >
              OK
            </button>
            <button
              type="button"
              onClick={() => setRenamingGroupId(null)}
              className="p-1 rounded-lg bg-slate-800 text-slate-400"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </form>
        )}

        {node.subgroups.map((sub) => renderGroupTree(sub, depth + 1, onSelectExtra))}
      </div>
    );
  };

  const parentFolderLabel = (() => {
    if (!groups) return "Vault Root";
    const pid = newGroupParentId ?? selectedGroupId;
    if (!pid || pid === groups.id) return "Vault Root";
    const trail = findGroupTrail(groups, pid);
    return trail ? trail[trail.length - 1].name : "Vault Root";
  })();

  return (
    <div className="h-full w-full flex flex-col app-shell overflow-hidden">
      {/* Top Bar — single safe-top inset */}
      <header className="safe-top px-3 sm:px-4 border-b app-header shrink-0">
        <div className="h-14 flex items-center justify-between gap-2 sm:gap-3">
          <button
            type="button"
            onClick={() => {
              setActiveTab("settings");
              setSelectedEntry(null);
              setCreatingNew(false);
            }}
            className="flex items-center gap-2.5 min-w-0 text-left hover:opacity-90 transition"
            title="View & edit vault properties"
          >
            <div className="w-9 h-9 rounded-lg overflow-hidden border cyber-accent-border shrink-0 bg-[#07090F]">
              <img src="/logo.png" alt="CipherPass" className="w-full h-full object-cover" />
            </div>
            <div className="min-w-0">
              <div className="text-sm font-bold text-white truncate">
                {status.database_name ?? "CipherPass"}
              </div>
              <div className="text-[10px] font-mono text-slate-400 flex items-center gap-1.5 truncate">
                <span className="cyber-accent-text">{status.cipher}</span>
                <span className="hidden xs:inline text-violet-300">· PQ</span>
                {status.kdf && (
                  <span className="hidden sm:inline">
                    · {status.kdf.algorithm} ({status.kdf.memory_mib} MiB / {status.kdf.iterations}r)
                  </span>
                )}
              </div>
            </div>
          </button>

          <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
            <span className="hidden lg:flex items-center gap-1 text-[10px] font-mono px-2 py-1 rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
              <WifiOff className="w-3 h-3" />
              OFFLINE
            </span>
            <UiStylePicker uiStyle={uiStyle} onChange={setUiStyle} compact />
            <ThemePicker theme={theme} onChange={setTheme} compact />
            <button
              type="button"
              onClick={async () => {
                try {
                  await vaultApi.clearClipboardNow();
                  showToast("Clipboard wiped immediately.");
                } catch {
                  showToast("Clipboard cleared.");
                }
              }}
              className="p-1.5 rounded-lg bg-slate-800/90 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-cyan-300 transition"
              title="Panic Wipe Clipboard Now"
            >
              <Eraser className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={() => {
                setActiveTab("vault");
                setSelectedEntry(null);
                setCreatingNew(true);
                setFocusTotpOnCreate(false);
              }}
              className="px-2.5 sm:px-3 py-1.5 rounded-lg cyber-btn-primary font-bold text-xs flex items-center gap-1.5 transition"
            >
              <Plus className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">New Entry</span>
            </button>
            <button
              type="button"
              onClick={handleLock}
              className="px-2.5 sm:px-3 py-1.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-rose-300 text-xs font-medium flex items-center gap-1.5 transition"
              title="Lock vault & zeroize RAM"
            >
              <Lock className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Lock</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Workspace */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* Desktop Sidebar */}
        <aside className="hidden md:flex w-64 flex-col border-r app-sidebar p-3 space-y-4 overflow-y-auto shrink-0">
          <nav className="space-y-1">
            <button
              type="button"
              onClick={() => {
                setActiveTab("vault");
                setFavoritesOnly(false);
                setSelectedGroupId(null);
              }}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition ${
                activeTab === "vault" && !favoritesOnly && !selectedGroupId
                  ? "bg-cyan-500/15 text-cyan-300 border border-cyan-400/25"
                  : "text-slate-300 hover:bg-slate-800/60"
              }`}
            >
              <KeyRound className="w-4 h-4" />
              All Credentials
            </button>
            <button
              type="button"
              onClick={() => {
                setActiveTab("vault");
                setFavoritesOnly(true);
                setSelectedGroupId(null);
              }}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition ${
                activeTab === "vault" && favoritesOnly
                  ? "bg-amber-500/15 text-amber-300 border border-amber-400/25"
                  : "text-slate-300 hover:bg-slate-800/60"
              }`}
            >
              <Star className="w-4 h-4" />
              Favorites
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("totp")}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition ${
                activeTab === "totp"
                  ? "bg-cyan-500/15 text-cyan-300 border border-cyan-400/25"
                  : "text-slate-300 hover:bg-slate-800/60"
              }`}
            >
              <ShieldCheck className="w-4 h-4" />
              2FA / TOTP Vault
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("generator")}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition ${
                activeTab === "generator"
                  ? "bg-violet-500/15 text-violet-300 border border-violet-400/25"
                  : "text-slate-300 hover:bg-slate-800/60"
              }`}
            >
              <Wand2 className="w-4 h-4" />
              CSPRNG Generator
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("audit")}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition ${
                activeTab === "audit"
                  ? "bg-emerald-500/15 text-emerald-300 border border-emerald-400/25"
                  : "text-slate-300 hover:bg-slate-800/60"
              }`}
            >
              <ShieldAlert className="w-4 h-4" />
              Security Audit
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("settings")}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition ${
                activeTab === "settings"
                  ? "bg-slate-700/60 text-white border border-slate-600"
                  : "text-slate-300 hover:bg-slate-800/60"
              }`}
            >
              <Settings className="w-4 h-4" />
              Vault, Import &amp; GUI
            </button>
          </nav>

          {/* Desktop Interactive Folder Tree */}
          <div className="pt-3 border-t border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between px-2">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Vault Folders
              </span>
              <button
                type="button"
                onClick={() => openCreateFolderForm(groups?.id ?? null)}
                className="text-slate-400 hover:text-cyan-300 flex items-center gap-1 text-[10px] font-semibold"
                title="Create new top-level folder"
              >
                <FolderPlus className="w-3.5 h-3.5" />
                New
              </button>
            </div>

            {showNewGroupInput && (
              <form onSubmit={handleCreateGroup} className="space-y-1.5 px-1">
                <div className="text-[10px] text-slate-400 truncate">
                  Inside: <span className="cyber-accent-text">{parentFolderLabel}</span>
                </div>
                <div className="flex gap-1">
                  <input
                    type="text"
                    value={newGroupName}
                    onChange={(e) => setNewGroupName(e.target.value)}
                    placeholder="Folder name..."
                    autoFocus
                    className="flex-1 min-w-0 rounded-lg bg-[#07090F] border border-slate-700 px-2 py-1 text-xs text-white"
                  />
                  <button
                    type="submit"
                    className="px-2 py-1 rounded-lg cyber-btn-primary text-xs font-semibold"
                  >
                    Add
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowNewGroupInput(false)}
                    className="p-1 rounded-lg bg-slate-800 text-slate-400"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              </form>
            )}

            {groups && <div className="space-y-0.5">{renderGroupTree(groups)}</div>}
          </div>
        </aside>

        {/* Center / Main Area */}
        {activeTab === "generator" ? (
          <main className="flex-1 overflow-y-auto p-4 sm:p-8 deck-animate">
            <div className="max-w-xl mx-auto cyber-panel rounded-2xl p-6 space-y-4">
              <h2 className="text-lg font-bold text-white">CSPRNG &amp; Diceware Generator</h2>
              <GeneratorPanel onCopy={handleCopy} />
            </div>
          </main>
        ) : activeTab === "audit" ? (
          <main className="flex-1 overflow-y-auto deck-animate">
            <AuditView onSelectEntry={handleSelectEntry} />
          </main>
        ) : activeTab === "settings" ? (
          <main className="flex-1 overflow-y-auto deck-animate">
            <SettingsView
              status={status}
              theme={theme}
              uiStyle={uiStyle}
              fontScale={fontScale}
              maskSubtitles={maskSubtitles}
              bgLockSeconds={bgLockSeconds}
              onThemeChange={setTheme}
              onUiStyleChange={setUiStyle}
              onFontScaleChange={setFontScale}
              onMaskSubtitlesChange={handleMaskSubtitlesChange}
              onBgLockSecondsChange={handleBgLockSecondsChange}
              onStatusUpdated={setStatus}
              onVaultDataChanged={refreshVaultData}
              onCopy={handleCopy}
            />
          </main>
        ) : activeTab === "totp" && !showingEditorMobile ? (
          <main className="flex-1 overflow-y-auto p-4 sm:p-6 deck-animate">
            <div className="max-w-4xl mx-auto space-y-5">
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div>
                  <h2 className="text-lg font-bold text-white flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 cyber-accent-text" />
                    Offline 2FA / TOTP Authenticator
                  </h2>
                  <p className="text-xs text-slate-400">
                    Live RFC 6238 tokens synced to your local device clock — zero cloud required.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setSelectedEntry(null);
                    setCreatingNew(true);
                    setFocusTotpOnCreate(true);
                  }}
                  className="px-3.5 py-2 rounded-xl cyber-btn-primary text-xs font-bold flex items-center gap-1.5"
                >
                  <Plus className="w-4 h-4" />
                  Add 2FA Token
                </button>
              </div>
              {entries.length === 0 ? (
                <div className="cyber-panel rounded-2xl p-8 text-center text-xs text-slate-400 space-y-3">
                  <p>No 2FA/TOTP tokens configured yet.</p>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedEntry(null);
                      setCreatingNew(true);
                      setFocusTotpOnCreate(true);
                    }}
                    className="px-4 py-2 rounded-xl cyber-btn-primary text-xs font-bold inline-flex items-center gap-1.5"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    Add Your First 2FA Token
                  </button>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                  {entries.map((item) => (
                    <div key={item.id} className="cyber-panel rounded-2xl p-4 space-y-3">
                      <div className="flex items-center justify-between gap-2">
                        <button
                          type="button"
                          onClick={() => handleSelectEntry(item.id)}
                          className="text-left min-w-0 hover:underline"
                        >
                          <div className="text-sm font-semibold text-white truncate">
                            {item.title}
                          </div>
                          <div className="text-[11px] font-mono text-slate-400 truncate">
                            {maskSubtitles ? "••••••••" : item.username || "—"}
                          </div>
                        </button>
                      </div>
                      {item.has_totp && (
                        <TotpBadge entryId={item.id} onCopy={handleCopy} compact />
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </main>
        ) : (
          <div className="flex-1 flex min-w-0 overflow-hidden">
            {/* Entry List Pane */}
            <section
              className={`${
                showingEditorMobile ? "hidden lg:flex" : "flex"
              } w-full lg:w-80 xl:w-96 flex-col border-r app-list-pane shrink-0`}
            >
              <div className="p-3 border-b border-slate-800/80 space-y-2.5">
                <div className="flex items-center gap-1.5">
                  <div className="relative flex-1 min-w-0">
                    <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      ref={searchInputRef}
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Instant local search... (Ctrl+K)"
                      className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 pl-9 pr-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-400"
                    />
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      const next = !maskSubtitles;
                      handleMaskSubtitlesChange(next);
                      showToast(
                        next
                          ? "Privacy mask ON — usernames & URLs hidden"
                          : "Privacy mask OFF"
                      );
                    }}
                    className={`p-2 rounded-xl border shrink-0 transition ${
                      maskSubtitles
                        ? "bg-emerald-500/20 border-emerald-400/50 text-emerald-300"
                        : "bg-[#07090F] border-slate-700/80 text-slate-400 hover:text-cyan-300"
                    }`}
                    title={
                      maskSubtitles
                        ? "Privacy Mask ON (click to show usernames/URLs)"
                        : "Privacy Mask OFF (click to hide usernames/URLs)"
                    }
                  >
                    {maskSubtitles ? (
                      <EyeOff className="w-4 h-4" />
                    ) : (
                      <Eye className="w-4 h-4" />
                    )}
                  </button>
                </div>

                {/* Recycle Bin Banner (when viewing Recycle Bin) */}
                {isViewingRecycleBin && (
                  <div className="rounded-xl bg-rose-500/10 border border-rose-500/35 px-3 py-2 flex items-center justify-between gap-2 text-[11px]">
                    <div className="flex items-center gap-1.5 text-rose-200 min-w-0">
                      <Trash2 className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                      <span className="truncate font-medium">
                        Recycle Bin ({entries.length})
                      </span>
                    </div>
                    {entries.length > 0 && (
                      <button
                        type="button"
                        onClick={async () => {
                          try {
                            const purged = await vaultApi.emptyRecycleBin();
                            setSelectedEntry(null);
                            await refreshVaultData();
                            showToast(
                              `Recycle Bin emptied — ${purged} entries permanently zeroized.`
                            );
                          } catch (err) {
                            showToast(String(err));
                          }
                        }}
                        className="px-2.5 py-1 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 border border-rose-400/40 text-[10px] font-bold text-rose-200 shrink-0"
                      >
                        Empty Trash
                      </button>
                    )}
                  </div>
                )}

                {/* Active Folder Breadcrumb Bar (Visible on Mobile & Desktop when inside a folder) */}
                {activeGroupTrail && activeGroupTrail.length > 1 && !isViewingRecycleBin && (
                  <div className="flex items-center justify-between gap-1.5 rounded-xl bg-[#07090F] border border-slate-800 px-2.5 py-1.5 text-[11px]">
                    <div className="flex items-center gap-1 min-w-0 overflow-x-auto">
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedGroupId(null);
                          setFavoritesOnly(false);
                        }}
                        className="text-slate-400 hover:text-cyan-300 shrink-0"
                      >
                        All
                      </button>
                      {activeGroupTrail.slice(1).map((node) => (
                        <React.Fragment key={node.id}>
                          <ChevronRight className="w-3 h-3 text-slate-500 shrink-0" />
                          <button
                            type="button"
                            onClick={() => setSelectedGroupId(node.id)}
                            className={`truncate font-medium ${
                              node.id === selectedGroupId
                                ? "cyber-accent-text"
                                : "text-slate-300 hover:text-cyan-300"
                            }`}
                          >
                            {node.name}
                          </button>
                        </React.Fragment>
                      ))}
                    </div>
                    {activeFolderNode && (
                      <button
                        type="button"
                        onClick={() => {
                          setShowFolderBrowserMobile(true);
                          openCreateFolderForm(activeFolderNode.id);
                        }}
                        className="text-[10px] px-2 py-0.5 rounded-md bg-slate-800 text-cyan-300 border border-slate-700 shrink-0"
                        title="Add subfolder here"
                      >
                        + Sub
                      </button>
                    )}
                  </div>
                )}

                {/* Mobile Folder Browser Toggle + Quick Pills */}
                <div className="flex md:hidden items-center gap-1.5 overflow-x-auto pb-0.5">
                  <button
                    type="button"
                    onClick={() => setShowFolderBrowserMobile(!showFolderBrowserMobile)}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold whitespace-nowrap border shrink-0 flex items-center gap-1 ${
                      showFolderBrowserMobile
                        ? "cyber-btn-primary border-transparent"
                        : "bg-slate-800 border-slate-700 text-cyan-200"
                    }`}
                  >
                    <FolderOpen className="w-3.5 h-3.5" />
                    Folders
                    <ChevronDown
                      className={`w-3 h-3 transition ${
                        showFolderBrowserMobile ? "rotate-180" : ""
                      }`}
                    />
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setFavoritesOnly(false);
                      setSelectedGroupId(null);
                    }}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-medium whitespace-nowrap border shrink-0 ${
                      !favoritesOnly && !selectedGroupId
                        ? "bg-cyan-500/15 border-cyan-400/40 text-cyan-200"
                        : "bg-[#07090F] border-slate-800 text-slate-400"
                    }`}
                  >
                    All
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setFavoritesOnly(true);
                      setSelectedGroupId(null);
                    }}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-medium whitespace-nowrap border shrink-0 flex items-center gap-1 ${
                      favoritesOnly
                        ? "bg-amber-500/15 border-amber-400/40 text-amber-200"
                        : "bg-[#07090F] border-slate-800 text-slate-400"
                    }`}
                  >
                    <Star className="w-3 h-3" />
                    Favs
                  </button>
                  {groups?.subgroups.map((sub) => {
                    const isBin = Boolean(status.recycle_bin_id && sub.id === status.recycle_bin_id);
                    return (
                      <button
                        key={sub.id}
                        type="button"
                        onClick={() => {
                          setFavoritesOnly(false);
                          setSelectedGroupId(sub.id);
                        }}
                        className={`px-2.5 py-1 rounded-lg text-[11px] font-medium whitespace-nowrap border shrink-0 flex items-center gap-1 ${
                          !favoritesOnly && selectedGroupId === sub.id
                            ? isBin
                              ? "bg-rose-500/15 border-rose-400/40 text-rose-200"
                              : "bg-cyan-500/15 border-cyan-400/40 text-cyan-200"
                            : "bg-[#07090F] border-slate-800 text-slate-400"
                        }`}
                      >
                        {isBin && <Trash2 className="w-3 h-3 text-rose-400" />}
                        {sub.name}
                      </button>
                    );
                  })}
                  <button
                    type="button"
                    onClick={() => {
                      setShowFolderBrowserMobile(true);
                      openCreateFolderForm(
                        isViewingRecycleBin ? groups?.id ?? null : selectedGroupId ?? groups?.id ?? null
                      );
                    }}
                    className="px-2 py-1 rounded-lg text-[11px] bg-slate-800 text-cyan-300 border border-slate-700 shrink-0"
                    title="New Folder"
                  >
                    + Folder
                  </button>
                </div>

                {/* Mobile Collapsible Full Folder Tree Browser (Create, Subfolder, Rename, Delete) */}
                {showFolderBrowserMobile && groups && (
                  <div className="md:hidden rounded-xl bg-[#07090F] border border-slate-800 p-2.5 space-y-2 max-h-64 overflow-y-auto deck-animate">
                    <div className="flex items-center justify-between px-1">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                        Browse &amp; Manage Vault Folders
                      </span>
                      <button
                        type="button"
                        onClick={() => openCreateFolderForm(groups.id)}
                        className="text-[10px] font-semibold cyber-accent-text flex items-center gap-1"
                      >
                        <FolderPlus className="w-3 h-3" />
                        + Root Folder
                      </button>
                    </div>

                    {showNewGroupInput && (
                      <form onSubmit={handleCreateGroup} className="space-y-1.5">
                        <div className="text-[10px] text-slate-400 px-1">
                          New folder inside:{" "}
                          <span className="cyber-accent-text font-medium">{parentFolderLabel}</span>
                        </div>
                        <div className="flex gap-1.5">
                          <input
                            type="text"
                            value={newGroupName}
                            onChange={(e) => setNewGroupName(e.target.value)}
                            placeholder="Folder name..."
                            autoFocus
                            className="flex-1 min-w-0 rounded-lg bg-[#0D111A] border border-slate-700 px-2.5 py-1.5 text-xs text-white"
                          />
                          <button
                            type="submit"
                            className="px-3 py-1.5 rounded-lg cyber-btn-primary text-xs font-bold"
                          >
                            Add
                          </button>
                          <button
                            type="button"
                            onClick={() => setShowNewGroupInput(false)}
                            className="p-1.5 rounded-lg bg-slate-800 text-slate-400"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </form>
                    )}

                    <div className="space-y-0.5">
                      {renderGroupTree(groups, 0, () => setShowFolderBrowserMobile(false))}
                    </div>
                  </div>
                )}
              </div>

              <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60">
                {entries.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500 space-y-2.5">
                    <p>
                      {isViewingRecycleBin
                        ? "Recycle Bin is empty."
                        : "No entries in this folder yet."}
                    </p>
                    {!isViewingRecycleBin && (
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedEntry(null);
                          setCreatingNew(true);
                          setFocusTotpOnCreate(false);
                        }}
                        className="px-4 py-2 rounded-xl cyber-btn-primary text-xs font-bold inline-flex items-center gap-1.5"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        Add Entry Here
                      </button>
                    )}
                  </div>
                ) : (
                  entries.map((item) => {
                    const active = selectedEntry?.id === item.id && !creatingNew;
                    return (
                      <div
                        key={item.id}
                        className={`px-3.5 py-3 flex items-center justify-between gap-2 transition ${
                          active
                            ? "bg-cyan-500/10 border-l-2 border-cyan-400"
                            : "hover:bg-slate-800/40"
                        }`}
                      >
                        <button
                          type="button"
                          onClick={() => handleSelectEntry(item.id)}
                          className="flex-1 min-w-0 text-left flex items-center gap-2.5"
                        >
                          <div className="w-8 h-8 rounded-lg bg-[#07090F] border border-slate-800 flex items-center justify-center shrink-0">
                            {renderEntryTypeIcon(item.entry_type)}
                          </div>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-1.5">
                              <span className="text-sm font-medium text-white truncate">
                                {item.title || "(Untitled)"}
                              </span>
                              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800/90 text-slate-300 border border-slate-700 shrink-0">
                                {entryTypeLabel(item.entry_type)}
                              </span>
                              {item.has_totp && item.entry_type !== "totp" && (
                                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shrink-0">
                                  2FA
                                </span>
                              )}
                              {item.favorite && (
                                <Star className="w-3.5 h-3.5 text-amber-400 fill-amber-400 shrink-0" />
                              )}
                            </div>
                            <div className="text-xs text-slate-400 truncate mt-0.5 font-mono">
                              {maskSubtitles
                                ? "••••••••"
                                : item.username || item.url || "Encrypted record"}
                            </div>
                          </div>
                        </button>

                        {/* 1-tap Quick Actions (Restore in Recycle Bin, Copy in normal folders) */}
                        <div className="flex items-center gap-1 shrink-0">
                          {isViewingRecycleBin ? (
                            <button
                              type="button"
                              onClick={async () => {
                                try {
                                  await vaultApi.restoreEntry(item.id);
                                  if (selectedEntry?.id === item.id) {
                                    setSelectedEntry(null);
                                  }
                                  await refreshVaultData();
                                  showToast(`"${item.title || "Entry"}" restored from Recycle Bin.`);
                                } catch (err) {
                                  showToast(String(err));
                                }
                              }}
                              className="px-2 py-1.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-400/40 text-emerald-300 text-[10px] font-semibold flex items-center gap-1 transition"
                              title="Restore entry out of Recycle Bin"
                            >
                              <RotateCcw className="w-3 h-3" />
                              Restore
                            </button>
                          ) : (
                            <>
                              {item.username && (
                                <button
                                  type="button"
                                  onClick={() => handleCopy(item.username, "Username")}
                                  className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-cyan-300 transition"
                                  title="Quick copy username"
                                >
                                  <User className="w-3.5 h-3.5" />
                                </button>
                              )}
                              {(item.entry_type === "login" || item.entry_type === "dev") && (
                                <button
                                  type="button"
                                  onClick={async () => {
                                    try {
                                      const secs = await vaultApi.copyEntryPassword(item.id);
                                      showToast(`Secret copied — clears in ${secs}s`);
                                    } catch (err) {
                                      showToast(String(err));
                                    }
                                  }}
                                  className="p-1.5 rounded-lg bg-slate-900 hover:bg-cyan-500/15 border border-slate-800 hover:border-cyan-400/30 text-slate-400 hover:text-cyan-300 transition"
                                  title="Quick copy password / token (auto-clear)"
                                >
                                  <Copy className="w-3.5 h-3.5" />
                                </button>
                              )}
                            </>
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </section>

            {/* Detail / Editor Pane */}
            <main
              className={`${
                showingEditorMobile ? "flex" : "hidden lg:flex"
              } flex-1 flex-col min-w-0 overflow-hidden`}
            >
              {(selectedEntry || creatingNew) && groups ? (
                <EntryEditor
                  entry={creatingNew ? null : selectedEntry}
                  defaultGroupId={defaultGroupId}
                  groups={groups}
                  initialFocusTotp={creatingNew && focusTotpOnCreate}
                  onSaved={(saved) => {
                    setSelectedEntry(saved);
                    setCreatingNew(false);
                    setFocusTotpOnCreate(false);
                    refreshVaultData();
                    showToast("Entry encrypted & saved atomically.");
                  }}
                  onDeleted={(permanentlyDeleted) => {
                    setSelectedEntry(null);
                    setCreatingNew(false);
                    setFocusTotpOnCreate(false);
                    refreshVaultData();
                    showToast(
                      permanentlyDeleted
                        ? "Entry permanently deleted & zeroized."
                        : "Entry moved to Recycle Bin (restorable)."
                    );
                  }}
                  onCopy={handleCopy}
                  onBackMobile={() => {
                    setSelectedEntry(null);
                    setCreatingNew(false);
                    setFocusTotpOnCreate(false);
                  }}
                />
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-center p-8 text-slate-500 space-y-3">
                  <Shield className="w-12 h-12 opacity-30" />
                  <div className="text-sm font-medium text-slate-400">
                    Select an entry or create a new credential
                  </div>
                  <div className="text-xs font-mono text-slate-500">
                    KDBX 4 ({status.cipher}) · NIST FIPS 203 ML-KEM-1024 Ready · Zeroize on Lock
                  </div>
                </div>
              )}
            </main>
          </div>
        )}
      </div>

      {/* Mobile Bottom Navigation — Interactive Sliding Liquid Glass Dock & Adaptive Nav */}
      <nav className="md:hidden safe-bottom border-t app-bottom-nav shrink-0 select-none">
        <div
          ref={dockRef}
          onTouchStart={handleDockTouchStart}
          onTouchMove={handleDockTouchMove}
          onTouchEnd={handleDockTouchEnd}
          onTouchCancel={handleDockTouchEnd}
          className="relative h-14 grid grid-cols-5 touch-pan-y"
        >
          {/* Animated Liquid Glass Sliding Lens Pill */}
          {uiStyle === "liquid-glass" && (
            <div
              className={`liquid-dock-slider ${dockDragging ? "dragging" : ""}`}
              style={{
                width: `${100 / MOBILE_NAV_ITEMS.length}%`,
                transform: `translateX(${sliderTransformPercent}%) scale(${
                  dockDragging ? 1.06 : 1
                })`,
              }}
            />
          )}

          {MOBILE_NAV_ITEMS.map((item, idx) => {
            const Icon = item.icon;
            const isActive =
              dockPreviewIdx !== null ? dockPreviewIdx === idx : activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => switchMobileTab(item.id)}
                className={`relative z-10 flex flex-col items-center justify-center gap-0.5 text-[10px] transition ${
                  isActive ? "cyber-accent-text font-semibold" : "text-slate-400"
                }`}
              >
                <span className={isActive && uiStyle !== "liquid-glass" ? "nav-pill-active" : ""}>
                  <Icon className="w-4 h-4" />
                </span>
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>
      </nav>

      {/* Toast Notification */}
      {toast && (
        <div className="fixed bottom-20 md:bottom-5 right-4 z-50 rounded-xl bg-[#0D111A] border border-cyan-400/40 px-4 py-2.5 text-xs text-cyan-200 shadow-xl cyber-glow">
          {toast}
        </div>
      )}
    </div>
  );
};

export default App;
