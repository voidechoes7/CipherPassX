export type CipherAlgorithm = "ChaCha20" | "Aes256Cbc";
export type KdfAlgorithm = "Argon2id" | "Argon2d";
export type EntryType = "login" | "card" | "totp" | "dev" | "note";

export interface KdfConfig {
  algorithm: KdfAlgorithm;
  memory_mib: number;
  iterations: number;
  parallelism: number;
  version: number;
}

export interface VaultStatus {
  unlocked: boolean;
  path: string | null;
  database_name: string | null;
  database_description: string | null;
  cipher: CipherAlgorithm | null;
  inner_cipher: string | null;
  kdbx_version: string | null;
  kdf: KdfConfig | null;
  has_master_password: boolean;
  has_keyfile: boolean;
  keyfile_path: string | null;
  compression: boolean;
  pq_armor_available: boolean;
  recycle_bin_id: string | null;
  entry_count: number;
  dirty: boolean;
  auto_lock_seconds: number;
  clipboard_clear_seconds: number;
}

export interface ChangeCredentialsResult {
  status: VaultStatus;
  biometric_reset: boolean;
}

export interface PqSelfTestResult {
  passed: boolean;
  algorithm: string;
  public_key_bytes: number;
  secret_key_bytes: number;
  ciphertext_bytes: number;
  elapsed_ms: number;
  fingerprint: string;
}

export interface GroupNode {
  id: string;
  name: string;
  notes: string;
  icon_id: number;
  entry_count: number;
  subgroups: GroupNode[];
}

export interface CustomField {
  key: string;
  value: string;
  protected: boolean;
}

export interface HistoryItem {
  index: number;
  title: string;
  username: string;
  password: string;
  modified_at: string;
}

export interface LocalVaultInfo {
  name: string;
  path: string;
  size_bytes: number;
}

export interface StorageRoot {
  label: string;
  path: string;
  writable: boolean;
}

export interface FolderListing {
  current_path: string;
  parent_path: string | null;
  writable: boolean;
  folders: string[];
  error: string | null;
}

export interface EntrySummary {
  id: string;
  group_id: string;
  entry_type: EntryType;
  title: string;
  username: string;
  url: string;
  favorite: boolean;
  has_totp: boolean;
  totp_uri: string | null;
  tags: string[];
  modified_at: string;
}

export interface EntryDetail {
  id: string;
  group_id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  favorite: boolean;
  tags: string[];
  totp_uri: string | null;
  custom_fields: CustomField[];
  history: HistoryItem[];
  created_at: string;
  modified_at: string;
  expires: boolean;
  expiry_time: string;
}

export interface EntryUpsertRequest {
  id: string | null;
  group_id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  favorite: boolean;
  tags: string[];
  totp_uri: string | null;
  custom_fields: CustomField[];
  expires: boolean;
  expiry_time: string | null;
}

export interface TotpCode {
  code: string;
  remaining_seconds: number;
  period: number;
  issuer: string;
  account: string;
}

export interface EntropyReport {
  entropy_bits: number;
  post_quantum_bits: number;
  strength: string;
  score: number;
}

export interface GeneratedSecret {
  value: string;
  entropy: EntropyReport;
}

export interface PasswordGenOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  exclude_ambiguous: boolean;
}

export interface PassphraseGenOptions {
  word_count: number;
  separator: string;
  capitalize: boolean;
  include_number: boolean;
}

export interface AuditIssueItem {
  entry_id: string;
  title: string;
  username: string;
  detail: string;
}

export interface SecurityAuditReport {
  total_entries: number;
  weak_passwords: AuditIssueItem[];
  reused_passwords: AuditIssueItem[];
  expired_entries: AuditIssueItem[];
  missing_totp_count: number;
  kdf_meets_safe_floor: boolean;
  kdf_summary: string;
  cipher_summary: string;
  post_quantum_ready: boolean;
  overall_score: number;
}

export interface MlKem1024Keypair {
  public_key_b64: string;
  secret_key_b64: string;
  fingerprint: string;
}

export interface ImportSummary {
  source_format: string;
  imported_entries: number;
  created_folders: number;
  skipped_items: number;
}

export interface CreateVaultFromImportResult {
  status: VaultStatus;
  summary: ImportSummary;
}
