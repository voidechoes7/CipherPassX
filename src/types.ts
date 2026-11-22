export type CipherAlgorithm = "ChaCha20" | "Aes256Cbc";
export type KdfAlgorithm = "Argon2id" | "Argon2d";

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
  cipher: CipherAlgorithm | null;
  kdf: KdfConfig | null;
  entry_count: number;
  dirty: boolean;
  auto_lock_seconds: number;
  clipboard_clear_seconds: number;
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

export interface EntrySummary {
  id: string;
  group_id: string;
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
