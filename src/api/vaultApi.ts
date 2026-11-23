import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { checkStatus as checkBiometricStatus } from "@tauri-apps/plugin-biometric";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import type {
  CipherAlgorithm,
  EntryDetail,
  EntrySummary,
  EntryUpsertRequest,
  EntropyReport,
  FolderListing,
  GeneratedSecret,
  GroupNode,
  KdfAlgorithm,
  KdfConfig,
  LocalVaultInfo,
  MlKem1024Keypair,
  PassphraseGenOptions,
  PasswordGenOptions,
  SecurityAuditReport,
  StorageRoot,
  TotpCode,
  VaultStatus,
} from "../types";

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function isMobilePlatform(): boolean {
  if (typeof navigator === "undefined") return false;
  return /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
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

  openVault: (req: {
    path: string;
    master_password: string | null;
    keyfile_path: string | null;
  }) => invoke<VaultStatus>("open_vault", { req }),

  lockVault: () => invoke<VaultStatus>("lock_vault"),
  saveVault: () => invoke<VaultStatus>("save_vault"),

  generateKeyfileToPath: (path: string) =>
    invoke<string>("generate_keyfile_to_path", { path }),

  listGroups: () => invoke<GroupNode>("list_groups"),

  createGroup: (parentId: string, name: string, iconId?: number) =>
    invoke<GroupNode>("create_group", {
      parentId,
      name,
      iconId: iconId ?? 48,
    }),

  deleteGroup: (groupId: string) => invoke<void>("delete_group", { groupId }),

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

  deleteEntry: (entryId: string) => invoke<void>("delete_entry", { entryId }),

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
    cipher?: CipherAlgorithm | null;
    kdf?: KdfConfig | null;
    auto_lock_seconds?: number | null;
    clipboard_clear_seconds?: number | null;
  }) => invoke<VaultStatus>("update_security_settings", { req }),

  runSecurityAudit: () => invoke<SecurityAuditReport>("run_security_audit_cmd"),

  exportVaultBackup: (destPath: string) =>
    invoke<string>("export_vault_backup", { destPath }),

  generatePqKeypair: () => invoke<MlKem1024Keypair>("generate_pq_keypair_cmd"),

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
