import React, { useCallback, useEffect, useState } from "react";
import {
  Eraser,
  Folder,
  FolderPlus,
  KeyRound,
  Lock,
  Plus,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Star,
  Wand2,
  WifiOff,
} from "lucide-react";
import { vaultApi } from "./api/vaultApi";
import { AuditView } from "./components/AuditView";
import { EntryEditor } from "./components/EntryEditor";
import { GeneratorPanel } from "./components/GeneratorPanel";
import { SettingsView } from "./components/SettingsView";
import { ThemePicker } from "./components/ThemePicker";
import { TotpBadge } from "./components/TotpBadge";
import { UnlockScreen } from "./components/UnlockScreen";
import { applyTheme, loadSavedTheme, type ThemeId } from "./themes";
import type { EntryDetail, EntrySummary, GroupNode, VaultStatus } from "./types";

type ActiveTab = "vault" | "totp" | "generator" | "audit" | "settings";

export const App: React.FC = () => {
  const [theme, setTheme] = useState<ThemeId>(() => loadSavedTheme());
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [groups, setGroups] = useState<GroupNode | null>(null);
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [selectedEntry, setSelectedEntry] = useState<EntryDetail | null>(null);
  const [creatingNew, setCreatingNew] = useState(false);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const [activeTab, setActiveTab] = useState<ActiveTab>("vault");
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [newGroupName, setNewGroupName] = useState("");
  const [showNewGroupInput, setShowNewGroupInput] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    setTimeout(() => {
      setToast((curr) => (curr === msg ? null : curr));
    }, 3500);
  }, []);

  const refreshVaultData = useCallback(async () => {
    try {
      const [g, list] = await Promise.all([
        vaultApi.listGroups(),
        vaultApi.listEntries({
          groupId: activeTab === "totp" ? null : selectedGroupId,
          query: searchQuery,
          favoritesOnly: activeTab === "totp" ? false : favoritesOnly,
          totpOnly: activeTab === "totp",
        }),
      ]);
      setGroups(g);
      setEntries(list);
    } catch {
      // Locked or unavailable
    }
  }, [activeTab, selectedGroupId, searchQuery, favoritesOnly]);

  useEffect(() => {
    vaultApi
      .getStatus()
      .then((s) => setStatus(s))
      .catch(() =>
        setStatus({
          unlocked: false,
          path: null,
          database_name: null,
          cipher: null,
          kdf: null,
          entry_count: 0,
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

  const handleLock = async () => {
    try {
      const s = await vaultApi.lockVault();
      setStatus(s);
      setSelectedEntry(null);
      setCreatingNew(false);
      setEntries([]);
      setGroups(null);
    } catch {
      setStatus((prev) => (prev ? { ...prev, unlocked: false } : prev));
    }
  };

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
      try {
        await navigator.clipboard.writeText(secret);
        showToast(`${label} copied`);
      } catch {
        showToast("Clipboard copy failed");
      }
    }
  };

  const handleCreateGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!groups || !newGroupName.trim()) return;
    try {
      await vaultApi.createGroup(groups.id, newGroupName.trim());
      setNewGroupName("");
      setShowNewGroupInput(false);
      await refreshVaultData();
    } catch (err) {
      showToast(String(err));
    }
  };

  if (!status || !status.unlocked) {
    return (
      <UnlockScreen
        theme={theme}
        onThemeChange={setTheme}
        onUnlocked={(s) => {
          setStatus(s);
          setActiveTab("vault");
        }}
      />
    );
  }

  const defaultGroupId =
    selectedGroupId ?? groups?.subgroups[0]?.id ?? groups?.id ?? "";

  const showingEditorMobile = Boolean(selectedEntry || creatingNew);

  const renderGroupTree = (node: GroupNode, depth = 0) => (
    <div key={node.id}>
      <button
        type="button"
        onClick={() => {
          setActiveTab("vault");
          setFavoritesOnly(false);
          setSelectedGroupId(depth === 0 ? null : node.id);
        }}
        style={{ paddingLeft: `${12 + depth * 12}px` }}
        className={`w-full flex items-center justify-between pr-3 py-1.5 rounded-lg text-xs transition ${
          activeTab === "vault" &&
          !favoritesOnly &&
          ((depth === 0 && selectedGroupId === null) || selectedGroupId === node.id)
            ? "bg-cyan-500/15 text-cyan-300 border border-cyan-400/25"
            : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
        }`}
      >
        <span className="flex items-center gap-2 truncate">
          <Folder className="w-3.5 h-3.5 shrink-0 text-cyan-400/80" />
          <span className="truncate">{depth === 0 ? "All Entries" : node.name}</span>
        </span>
        {node.entry_count > 0 && (
          <span className="text-[10px] font-mono text-slate-500">{node.entry_count}</span>
        )}
      </button>
      {node.subgroups.map((sub) => renderGroupTree(sub, depth + 1))}
    </div>
  );

  return (
    <div className="h-full flex flex-col bg-[#07090F] text-slate-100 overflow-hidden">
      {/* Top Bar */}
      <header className="h-14 px-4 border-b border-slate-800/90 bg-[#0D111A] flex items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="w-9 h-9 rounded-lg overflow-hidden border border-cyan-400/35 shrink-0 bg-[#07090F]">
            <img src="/logo.png" alt="CipherPass" className="w-full h-full object-cover" />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-bold text-white truncate">
              {status.database_name ?? "CipherPass"}
            </div>
            <div className="text-[10px] font-mono text-slate-400 flex items-center gap-2">
              <span className="text-cyan-300">{status.cipher}</span>
              {status.kdf && (
                <span className="hidden sm:inline">
                  · {status.kdf.algorithm} ({status.kdf.memory_mib} MiB / {status.kdf.iterations}r)
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
          <span className="hidden md:flex items-center gap-1 text-[10px] font-mono px-2 py-1 rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
            <WifiOff className="w-3 h-3" />
            OFFLINE
          </span>
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
      </header>

      {/* Main Workspace */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* Desktop Sidebar */}
        <aside className="hidden md:flex w-60 flex-col border-r border-slate-800/80 bg-[#0B0F17] p-3 space-y-4 overflow-y-auto shrink-0">
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
              Crypto Settings
            </button>
          </nav>

          {/* Groups */}
          <div className="pt-3 border-t border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between px-2">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Folders
              </span>
              <button
                type="button"
                onClick={() => setShowNewGroupInput(!showNewGroupInput)}
                className="text-slate-400 hover:text-cyan-300"
                title="New Folder"
              >
                <FolderPlus className="w-3.5 h-3.5" />
              </button>
            </div>

            {showNewGroupInput && (
              <form onSubmit={handleCreateGroup} className="flex gap-1 px-1">
                <input
                  type="text"
                  value={newGroupName}
                  onChange={(e) => setNewGroupName(e.target.value)}
                  placeholder="Folder name..."
                  className="flex-1 min-w-0 rounded bg-[#07090F] border border-slate-700 px-2 py-1 text-xs text-white"
                />
                <button
                  type="submit"
                  className="px-2 py-1 rounded bg-cyan-500 text-slate-950 text-xs font-semibold"
                >
                  Add
                </button>
              </form>
            )}

            {groups && <div className="space-y-0.5">{renderGroupTree(groups)}</div>}
          </div>
        </aside>

        {/* Center / Main Area */}
        {activeTab === "generator" ? (
          <main className="flex-1 overflow-y-auto p-4 sm:p-8">
            <div className="max-w-xl mx-auto cyber-panel rounded-2xl p-6 space-y-4">
              <h2 className="text-lg font-bold text-white">CSPRNG &amp; Diceware Generator</h2>
              <GeneratorPanel onCopy={handleCopy} />
            </div>
          </main>
        ) : activeTab === "audit" ? (
          <main className="flex-1 overflow-y-auto">
            <AuditView onSelectEntry={handleSelectEntry} />
          </main>
        ) : activeTab === "settings" ? (
          <main className="flex-1 overflow-y-auto">
            <SettingsView
              status={status}
              theme={theme}
              onThemeChange={setTheme}
              onStatusUpdated={setStatus}
            />
          </main>
        ) : activeTab === "totp" && !showingEditorMobile ? (
          <main className="flex-1 overflow-y-auto p-4 sm:p-6">
            <div className="max-w-4xl mx-auto space-y-5">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-lg font-bold text-white flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 cyber-accent-text" />
                    Offline 2FA / TOTP Authenticator
                  </h2>
                  <p className="text-xs text-slate-400">
                    Live RFC 6238 tokens synced to your local device clock — zero cloud required.
                  </p>
                </div>
              </div>
              {entries.length === 0 ? (
                <div className="cyber-panel rounded-2xl p-8 text-center text-xs text-slate-400 space-y-2">
                  <p>No 2FA/TOTP tokens configured yet.</p>
                  <p className="text-slate-500">
                    Open any entry and paste an <code className="text-cyan-300">otpauth://</code> URI or Base32 secret.
                  </p>
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
                            {item.username || "—"}
                          </div>
                        </button>
                      </div>
                      {item.totp_uri && (
                        <TotpBadge uriOrSecret={item.totp_uri} onCopy={handleCopy} compact />
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
              } w-full lg:w-80 xl:w-96 flex-col border-r border-slate-800/80 bg-[#0A0E16] shrink-0`}
            >
              <div className="p-3 border-b border-slate-800/80">
                <div className="relative">
                  <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Instant local search..."
                    className="w-full rounded-xl bg-[#07090F] border border-slate-700/80 pl-9 pr-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-400"
                  />
                </div>
              </div>

              <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60">
                {entries.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500 space-y-2">
                    <p>No entries match this filter.</p>
                    <button
                      type="button"
                      onClick={() => {
                        setSelectedEntry(null);
                        setCreatingNew(true);
                      }}
                      className="text-cyan-400 hover:underline"
                    >
                      + Create your first entry
                    </button>
                  </div>
                ) : (
                  entries.map((item) => {
                    const active = selectedEntry?.id === item.id && !creatingNew;
                    return (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => handleSelectEntry(item.id)}
                        className={`w-full text-left px-4 py-3 transition ${
                          active
                            ? "bg-cyan-500/10 border-l-2 border-cyan-400"
                            : "hover:bg-slate-800/40"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-sm font-medium text-white truncate">
                            {item.title || "(Untitled)"}
                          </span>
                          <div className="flex items-center gap-1.5 shrink-0">
                            {item.has_totp && (
                              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                                2FA
                              </span>
                            )}
                            {item.favorite && (
                              <Star className="w-3.5 h-3.5 text-amber-400 fill-amber-400" />
                            )}
                          </div>
                        </div>
                        <div className="text-xs text-slate-400 truncate mt-0.5 font-mono">
                          {item.username || item.url || "—"}
                        </div>
                      </button>
                    );
                  })
                )}
              </div>
            </section>

            {/* Detail / Editor Pane */}
            <main
              className={`${
                showingEditorMobile ? "flex" : "hidden lg:flex"
              } flex-1 flex-col min-w-0 bg-[#07090F] overflow-hidden`}
            >
              {(selectedEntry || creatingNew) && groups ? (
                <EntryEditor
                  entry={creatingNew ? null : selectedEntry}
                  defaultGroupId={defaultGroupId}
                  groups={groups}
                  onSaved={(saved) => {
                    setSelectedEntry(saved);
                    setCreatingNew(false);
                    refreshVaultData();
                    showToast("Entry encrypted & saved atomically.");
                  }}
                  onDeleted={() => {
                    setSelectedEntry(null);
                    setCreatingNew(false);
                    refreshVaultData();
                    showToast("Entry deleted & zeroized.");
                  }}
                  onCopy={handleCopy}
                  onBackMobile={() => {
                    setSelectedEntry(null);
                    setCreatingNew(false);
                  }}
                />
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-center p-8 text-slate-500 space-y-3">
                  <Shield className="w-12 h-12 text-slate-800" />
                  <div className="text-sm font-medium text-slate-400">
                    Select an entry or create a new credential
                  </div>
                  <div className="text-xs font-mono text-slate-600">
                    ChaCha20 Inner Stream · HMAC-SHA256 Authenticated · Zeroize on Lock
                  </div>
                </div>
              )}
            </main>
          </div>
        )}
      </div>

      {/* Mobile Bottom Navigation */}
      <nav className="md:hidden h-14 border-t border-slate-800 bg-[#0D111A] grid grid-cols-5 shrink-0">
        {[
          { id: "vault" as const, icon: KeyRound, label: "Vault" },
          { id: "totp" as const, icon: ShieldCheck, label: "2FA" },
          { id: "generator" as const, icon: Wand2, label: "Gen" },
          { id: "audit" as const, icon: ShieldAlert, label: "Audit" },
          { id: "settings" as const, icon: Settings, label: "Crypto" },
        ].map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                setActiveTab(item.id);
                setSelectedEntry(null);
                setCreatingNew(false);
              }}
              className={`flex flex-col items-center justify-center gap-0.5 text-[10px] ${
                isActive ? "text-cyan-400" : "text-slate-400"
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Toast Notification */}
      {toast && (
        <div className="fixed bottom-16 md:bottom-5 right-4 z-50 rounded-xl bg-[#0D111A] border border-cyan-400/40 px-4 py-2.5 text-xs text-cyan-200 shadow-xl cyber-glow">
          {toast}
        </div>
      )}
    </div>
  );
};

export default App;
