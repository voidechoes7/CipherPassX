import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { checkStatus as checkBiometricStatus } from "@tauri-apps/plugin-biometric";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import type {
  ChangeCredentialsResult,
  CipherAlgorithm,
  CreateVaultFromImportResult,
  EntryDetail,
  EntrySummary,
  EntryUpsertRequest,
  EntropyReport,
  FolderListing,
  GeneratedSecret,
  GroupNode,
  ImportSummary,
  KdfAlgorithm,
  KdfConfig,
  LocalVaultInfo,
  MlKem1024Keypair,
  PassphraseGenOptions,
  PasswordGenOptions,
  PqSelfTestResult,
  SecurityAuditReport,
  StorageRoot,
  TotpCode,
  VaultStatus,
} from "../types";

const HIDE_RECENT_KEY = "cipherpass_hide_recent_vaults_v1";
const SCREEN_PROTECT_KEY = "cipherpass_screen_protect_v1";
const MASK_SUBTITLES_KEY = "cipherpass_mask_subtitles_v1";
const BG_LOCK_SECS_KEY = "cipherpass_bg_lock_secs_v1";

export function loadHideRecentVaults(): boolean {
  try {
    return localStorage.getItem(HIDE_RECENT_KEY) === "true";
  } catch {
    return false;
  }
}

export function saveHideRecentVaults(hide: boolean): void {
  try {
    localStorage.setItem(HIDE_RECENT_KEY, hide ? "true" : "false");
  } catch {
    // ignore storage restrictions
  }
}

export function loadScreenProtection(): boolean {
  try {
    const val = localStorage.getItem(SCREEN_PROTECT_KEY);
    return val === null ? true : val === "true";
  } catch {
    return true;
  }
}

export function applyScreenProtection(enabled: boolean): void {
  try {
    localStorage.setItem(SCREEN_PROTECT_KEY, enabled ? "true" : "false");
  } catch {
    // ignore
  }
  try {
    window.CipherPassAndroid?.setScreenProtection?.(enabled);
  } catch {
    // ignore on non-Android
  }
}

export function loadMaskEntrySubtitles(): boolean {
  try {
    return localStorage.getItem(MASK_SUBTITLES_KEY) === "true";
  } catch {
    return false;
  }
}

export function saveMaskEntrySubtitles(masked: boolean): void {
  try {
    localStorage.setItem(MASK_SUBTITLES_KEY, masked ? "true" : "false");
  } catch {
    // ignore
  }
}

export function loadBackgroundLockSeconds(): number {
  try {
    const raw = localStorage.getItem(BG_LOCK_SECS_KEY);
    const n = raw ? Number(raw) : 0;
    return Number.isFinite(n) && n >= 0 ? n : 0;
  } catch {
    return 0;
  }
}

export function saveBackgroundLockSeconds(secs: number): void {
  try {
    localStorage.setItem(BG_LOCK_SECS_KEY, String(Math.max(0, secs)));
  } catch {
    // ignore
  }
}

export function onAndroidAppBackgrounded(cb: (ts: number) => void): () => void {
  if (typeof window === "undefined") return () => {};
  const handler = (ev: Event) => {
    const custom = ev as CustomEvent<{ ts?: number }>;
    cb(custom.detail?.ts ?? Date.now());
  };
  window.addEventListener("cipherpass-app-backgrounded", handler);
  return () => window.removeEventListener("cipherpass-app-backgrounded", handler);
}

interface CipherPassAndroidBridge {
  hasAllFilesAccess?: () => boolean;
  requestAllFilesAccess?: () => boolean;
  pickNativeFolder?: (defaultFileName: string) => boolean;
  setScreenProtection?: (enabled: boolean) => boolean;
  setSystemBarsAppearance?: (isLight: boolean, bgColorHex: string) => boolean;
}

declare global {
  interface Window {
    CipherPassAndroid?: CipherPassAndroidBridge;
  }
}

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function isMobilePlatform(): boolean {
  if (typeof navigator === "undefined") return false;
  return /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
}

export function isAndroidPlatform(): boolean {
  if (typeof navigator === "undefined") return false;
  return /Android/i.test(navigator.userAgent);
}

export function hasAndroidStorageBridge(): boolean {
  return typeof window !== "undefined" && Boolean(window.CipherPassAndroid);
}

export function hasAndroidAllFilesAccess(): boolean {
  if (!isAndroidPlatform()) return true;
  try {
    if (window.CipherPassAndroid?.hasAllFilesAccess) {
      return Boolean(window.CipherPassAndroid.hasAllFilesAccess());
    }
  } catch {
    // Fallback to Rust writable checks
  }
  return false;
}

export function requestAndroidAllFilesAccess(): boolean {
  if (!isAndroidPlatform()) return false;
  try {
    if (window.CipherPassAndroid?.requestAllFilesAccess) {
      return Boolean(window.CipherPassAndroid.requestAllFilesAccess());
    }
  } catch {
    return false;
  }
  return false;
}

export function onAndroidStoragePermissionChanged(
  cb: (granted: boolean) => void
): () => void {
  if (typeof window === "undefined") return () => {};
  const handler = (ev: Event) => {
    const custom = ev as CustomEvent<{ granted?: boolean }>;
    cb(Boolean(custom.detail?.granted));
  };
  window.addEventListener("cipherpass-storage-permission-changed", handler);
  return () =>
    window.removeEventListener("cipherpass-storage-permission-changed", handler);
}

export function pickNativeAndroidFolder(
  defaultFileName = "CipherPass_Vault.kdbx"
): Promise<{ path: string | null; error: string | null }> {
  if (
    typeof window === "undefined" ||
    !window.CipherPassAndroid?.pickNativeFolder
  ) {
    return Promise.resolve({
      path: null,
      error: "Native Android folder picker is unavailable on this platform.",
    });
  }

  return new Promise((resolve) => {
    let settled = false;
    const handler = (ev: Event) => {
      if (settled) return;
      settled = true;
      window.removeEventListener("cipherpass-native-folder-picked", handler);
      const custom = ev as CustomEvent<{ path?: string | null; error?: string | null }>;
      resolve({
        path: custom.detail?.path ?? null,
        error: custom.detail?.error ?? null,
      });
    };

    window.addEventListener("cipherpass-native-folder-picked", handler);
    try {
      const launched = window.CipherPassAndroid?.pickNativeFolder?.(defaultFileName);
      if (!launched && !settled) {
        settled = true;
        window.removeEventListener("cipherpass-native-folder-picked", handler);
        resolve({
          path: null,
          error: "Could not launch the native Android folder picker.",
        });
      }
    } catch (err) {
      if (!settled) {
        settled = true;
        window.removeEventListener("cipherpass-native-folder-picked", handler);
        resolve({ path: null, error: String(err) });
      }
    }
  });
}

export async function checkBiometricAvailable(): Promise<boolean> {
  if (!isTauriRuntime() || !isMobilePlatform()) return false;
  try {
    const status = await checkBiometricStatus();
    return Boolean(status.isAvailable);
  } catch {
    return false;
  }
}

export async function pickOpenKdbxFile(): Promise<string | null> {
  if (!isTauriRuntime()) return null;
  const selected = await openDialog({
    multiple: false,
    ...(isMobilePlatform()
      ? {}
      : { filters: [{ name: "KeePass KDBX 4 Database", extensions: ["kdbx"] }] }),
  });
  return typeof selected === "string" ? selected : null;
}

export async function pickSaveKdbxFile(defaultName = "CipherPass.kdbx"): Promise<string | null> {
  if (!isTauriRuntime()) return null;
  // On Android/iOS, omitting custom MIME filters prevents SAF ACTION_CREATE_DOCUMENT
  // from disabling the "Save" button in certain file managers.
  const selected = await saveDialog({
    defaultPath: defaultName,
    ...(isMobilePlatform()
      ? {}
      : { filters: [{ name: "KeePass KDBX 4 Database", extensions: ["kdbx"] }] }),
  });
  return typeof selected === "string" ? selected : null;
}

export async function pickFolder(): Promise<string | null> {
  if (!isTauriRuntime()) return null;
  const selected = await openDialog({
    directory: true,
    multiple: false,
  });
  return typeof selected === "string" ? selected : null;
}

export async function pickOpenKeyfile(): Promise<string | null> {
  if (!isTauriRuntime()) return null;
  const selected = await openDialog({
    multiple: false,
    ...(isMobilePlatform()
      ? {}
      : { filters: [{ name: "KeePass Keyfile", extensions: ["keyx", "key", "xml"] }] }),
  });
  return typeof selected === "string" ? selected : null;
}

export async function pickSaveKeyfile(defaultName = "CipherPass.keyx"): Promise<string | null> {
  if (!isTauriRuntime()) return null;
  const selected = await saveDialog({
    defaultPath: defaultName,
    ...(isMobilePlatform()
      ? {}
      : { filters: [{ name: "KeePass Keyfile v2.0 XML", extensions: ["keyx", "xml"] }] }),
  });
  return typeof selected === "string" ? selected : null;
}

export async function pickSavePqFile(defaultName = "CipherPass.kdbx.pq"): Promise<string | null> {
  if (!isTauriRuntime()) return null;
  const selected = await saveDialog({
    defaultPath: defaultName,
    ...(isMobilePlatform()
      ? {}
      : { filters: [{ name: "CipherPass ML-KEM-1024 Vault", extensions: ["pq"] }] }),
  });
  return typeof selected === "string" ? selected : null;
}

export async function pickOpenPqFile(): Promise<string | null> {
  if (!isTauriRuntime()) return null;
  const selected = await openDialog({
    multiple: false,
    ...(isMobilePlatform()
      ? {}
      : { filters: [{ name: "CipherPass ML-KEM-1024 Vault", extensions: ["pq"] }] }),
  });
  return typeof selected === "string" ? selected : null;
}

export async function pickOpenJsonFile(): Promise<string | null> {
  if (!isTauriRuntime()) return null;
  const selected = await openDialog({
    multiple: false,
    ...(isMobilePlatform()
      ? {}
      : { filters: [{ name: "Bitwarden / Encrypted JSON", extensions: ["json"] }] }),
  });
  return typeof selected === "string" ? selected : null;
}

export async function pickSaveJsonFile(
  defaultName = "CipherPass_Encrypted_Export.json"
): Promise<string | null> {
  if (!isTauriRuntime()) return null;
  const selected = await saveDialog({
    defaultPath: defaultName,
    ...(isMobilePlatform()
      ? {}
      : { filters: [{ name: "Encrypted JSON Backup", extensions: ["json"] }] }),
  });
  return typeof selected === "string" ? selected : null;
}

export async function pickOpenCsvFile(): Promise<string | null> {
  if (!isTauriRuntime()) return null;
  const selected = await openDialog({
    multiple: false,
    ...(isMobilePlatform()
      ? {}
      : { filters: [{ name: "Bitwarden / KeePass CSV", extensions: ["csv"] }] }),
  });
  return typeof selected === "string" ? selected : null;
}

export async function pickOpenPqKeyFile(): Promise<string | null> {
  if (!isTauriRuntime()) return null;
  const selected = await openDialog({
    multiple: false,
    ...(isMobilePlatform()
      ? {}
      : { filters: [{ name: "ML-KEM-1024 Key File", extensions: ["pqkey", "pqpub", "txt"] }] }),
  });
  return typeof selected === "string" ? selected : null;
}

export async function pickSavePqKeyFile(
  defaultName = "CipherPass_MLKEM1024_SECRET.pqkey"
): Promise<string | null> {
  if (!isTauriRuntime()) return null;
  const selected = await saveDialog({
    defaultPath: defaultName,
    ...(isMobilePlatform()
      ? {}
      : { filters: [{ name: "ML-KEM-1024 Key File", extensions: ["pqkey", "pqpub", "txt"] }] }),
  });
  return typeof selected === "string" ? selected : null;
}

export const vaultApi = {
  getDefaultVaultDir: () => invoke<string>("get_default_vault_dir"),
  getStorageRoots: () => invoke<StorageRoot[]>("get_storage_roots"),
  listDirectoryFolders: (path: string) =>
    invoke<FolderListing>("list_directory_folders", { path }),
  createDirectory: (parentPath: string, folderName: string) =>
    invoke<string>("create_directory", { parentPath, folderName }),
  moveVaultToPath: (destPath: string) =>
    invoke<VaultStatus>("move_vault_to_path", { destPath }),
  copyEntryPassword: (entryId: string) =>
    invoke<number>("copy_entry_password", { entryId }),
  listLocalVaults: () => invoke<LocalVaultInfo[]>("list_local_vaults"),
  clearRecentVaults: () => invoke<void>("clear_recent_vaults"),
  clearClipboardNow: () => invoke<void>("clear_clipboard_now"),
  hasBiometricSlot: (path: string) => invoke<boolean>("has_biometric_slot", { path }),
  enableBiometricUnlock: () => invoke<boolean>("enable_biometric_unlock"),
  disableBiometricUnlock: () => invoke<boolean>("disable_biometric_unlock"),
  unlockVaultBiometric: (path: string) => invoke<VaultStatus>("unlock_vault_biometric", { path }),
  getStatus: () => invoke<VaultStatus>("get_vault_status"),

  createVault: (req: {
    path: string;
    database_name: string;
    master_password: string | null;
    keyfile_path: string | null;
    cipher: CipherAlgorithm;
    kdf_algorithm: KdfAlgorithm;
    memory_mib: number;
    iterations: number;
    parallelism: number;
  }) => invoke<VaultStatus>("create_vault", { req }),

  createVaultFromImport: (req: {
    path: string;
    database_name: string;
    master_password: string | null;
    keyfile_path: string | null;
    cipher: CipherAlgorithm;
    kdf_algorithm: KdfAlgorithm;
    memory_mib: number;
    iterations: number;
    parallelism: number;
    import_kind: "bitwarden_json" | "csv";
    import_source_path: string;
    import_password: string | null;
  }) => invoke<CreateVaultFromImportResult>("create_vault_from_import", { req }),

  openVault: (req: {
    path: string;
    master_password: string | null;
    keyfile_path: string | null;
  }) => invoke<VaultStatus>("open_vault", { req }),

  lockVault: () => invoke<VaultStatus>("lock_vault"),
  saveVault: () => invoke<VaultStatus>("save_vault"),

  generateKeyfileToPath: (path: string) =>
    invoke<string>("generate_keyfile_to_path", { path }),

  writeTextFile: (path: string, content: string) =>
    invoke<string>("write_text_file", { path, content }),

  readTextFile: (path: string) => invoke<string>("read_text_file", { path }),

  listGroups: () => invoke<GroupNode>("list_groups"),

  createGroup: (parentId: string, name: string, iconId?: number) =>
    invoke<GroupNode>("create_group", {
      parentId,
      name,
      iconId: iconId ?? 48,
    }),

  renameGroup: (groupId: string, name: string) =>
    invoke<GroupNode>("rename_group", { groupId, name }),

  deleteGroup: (groupId: string) => invoke<void>("delete_group", { groupId }),

  importBitwardenJsonFile: (srcPath: string, exportPassword?: string | null) =>
    invoke<ImportSummary>("import_bitwarden_json_file", {
      srcPath,
      exportPassword: exportPassword ?? null,
    }),

  importCsvFile: (srcPath: string) =>
    invoke<ImportSummary>("import_csv_file", { srcPath }),

  importKdbxIntoVault: (
    srcPath: string,
    masterPassword?: string | null,
    keyfilePath?: string | null
  ) =>
    invoke<ImportSummary>("import_kdbx_into_vault", {
      srcPath,
      masterPassword: masterPassword ?? null,
      keyfilePath: keyfilePath ?? null,
    }),

  exportEncryptedJsonFile: (destPath: string, exportPassword: string) =>
    invoke<string>("export_encrypted_json_file", {
      destPath,
      exportPassword,
    }),

  listEntries: (params: {
    groupId?: string | null;
    query?: string;
    favoritesOnly?: boolean;
    totpOnly?: boolean;
  }) =>
    invoke<EntrySummary[]>("list_entries", {
      groupId: params.groupId ?? null,
      query: params.query ?? null,
      favoritesOnly: params.favoritesOnly ?? false,
      totpOnly: params.totpOnly ?? false,
    }),

  getEntry: (entryId: string) => invoke<EntryDetail>("get_entry", { entryId }),

  upsertEntry: (req: EntryUpsertRequest) =>
    invoke<EntryDetail>("upsert_entry", { req }),

  deleteEntry: (entryId: string) => invoke<boolean>("delete_entry", { entryId }),

  restoreEntry: (entryId: string, targetGroupId?: string | null) =>
    invoke<EntryDetail>("restore_entry", {
      entryId,
      targetGroupId: targetGroupId ?? null,
    }),

  emptyRecycleBin: () => invoke<number>("empty_recycle_bin"),

  toggleFavorite: (entryId: string) =>
    invoke<EntryDetail>("toggle_favorite", { entryId }),

  getTotpCode: (uriOrSecret: string) =>
    invoke<TotpCode>("get_totp_code", { uriOrSecret }),

  generatePassword: (options: PasswordGenOptions) =>
    invoke<GeneratedSecret>("generate_password_cmd", { options }),

  generatePassphrase: (options: PassphraseGenOptions) =>
    invoke<GeneratedSecret>("generate_passphrase_cmd", { options }),

  evaluatePassword: (password: string) =>
    invoke<EntropyReport>("evaluate_password_cmd", { password }),

  copySecretWithAutoClear: (secret: string, clearSeconds?: number) =>
    invoke<number>("copy_secret_with_auto_clear", {
      secret,
      clearSeconds: clearSeconds ?? null,
    }),

  updateSecuritySettings: (req: {
    database_name?: string | null;
    database_description?: string | null;
    cipher?: CipherAlgorithm | null;
    kdf?: KdfConfig | null;
    auto_lock_seconds?: number | null;
    clipboard_clear_seconds?: number | null;
  }) => invoke<VaultStatus>("update_security_settings", { req }),

  changeMasterCredentials: (req: {
    current_password?: string | null;
    new_password?: string | null;
    keyfile_action: "keep" | "set" | "remove";
    new_keyfile_path?: string | null;
  }) => invoke<ChangeCredentialsResult>("change_master_credentials", { req }),

  runSecurityAudit: () => invoke<SecurityAuditReport>("run_security_audit_cmd"),

  exportVaultBackup: (destPath: string) =>
    invoke<string>("export_vault_backup", { destPath }),

  generatePqKeypair: () => invoke<MlKem1024Keypair>("generate_pq_keypair_cmd"),

  runPqSelfTest: () => invoke<PqSelfTestResult>("run_pq_self_test"),

  exportPqArmoredVault: (destPath: string, publicKeyB64: string) =>
    invoke<string>("export_pq_armored_vault", {
      destPath,
      publicKeyB64,
    }),

  unsealPqArmoredVault: (
    srcPqPath: string,
    destKdbxPath: string,
    secretKeyB64: string
  ) =>
    invoke<string>("unseal_pq_armored_vault", {
      srcPqPath,
      destKdbxPath,
      secretKeyB64,
    }),

  onAutoLocked: (cb: () => void) =>
    isTauriRuntime() ? listen("vault-auto-locked", cb) : Promise.resolve(() => {}),

  onClipboardCleared: (cb: () => void) =>
    isTauriRuntime() ? listen("clipboard-cleared", cb) : Promise.resolve(() => {}),
};
