# CipherPass

**100% Offline, Post-Quantum Hardened, Multiplatform KeePass KDBX 4 / 4.1 Password Manager** built with pure Rust (`#![forbid(unsafe_code)]`) and Tauri 2 for **Linux (`.deb` / `.AppImage`)**, **Windows (`.exe`)**, **Android (`.apk`)**, and **iOS (`.ipa`)**.

> **HONEST PRE-AUDIT SECURITY NOTICE**
> CipherPass implements standard KeePass KDBX 4 / 4.1 cryptography in pure Rust with `#![forbid(unsafe_code)]`, zero network sockets, and zero telemetry. However, **this codebase has not yet undergone an independent third-party cryptographic audit**. Always maintain verified offline backups of your `.kdbx` vault files.

---

## Cryptographic Architecture (KDBX 4 / 4.1 Standard)

| Layer | Implementation | Security Property |
| :--- | :--- | :--- |
| **Core Engine** | Pure Rust (`crates/cipherpass-core`, `#![forbid(unsafe_code)]`) | Memory-safe, zero `unsafe` blocks |
| **Format** | KeePass **KDBX 4.0 / 4.1** | Full interoperability with **KeePassXC** & **KeePassDX** |
| **KDF** | **Argon2id (v0x13)** & **Argon2d** | Configurable Memory (MiB ≥ 64), Rounds (≥ 3), Lanes (≥ 1) |
| **Outer Cipher** | **ChaCha20** (default) & **AES-256-CBC** | 256-bit keys → **128-bit Post-Quantum security** against Grover's algorithm |
| **Authentication** | **HMAC-SHA256** (Header + 64 KiB Block Stream) + Header SHA-256 | Constant-time (`subtle`) tamper detection on every header & block |
| **Second Factor** | Optional **Keyfile v2.0 XML** (256-bit CSPRNG + SHA-256 hash prefix) | Also reads Keyfile v1.0 XML, 32-byte raw, and 64-byte hex keyfiles |
| **In-Memory Protection** | **ChaCha20 Inner Stream** + **`zeroize` / `ZeroizeOnDrop`** | Protected fields encrypted in XML; secrets wiped on lock or drop |
| **Atomic Persistence** | `.tmp.<rand>` → `flush` → `sync_all` (fsync) → atomic `rename` | Safe for iCloud / Syncthing / Google Drive folder sync |
| **Network Surface** | **Zero telemetry, zero servers, zero network calls** | Strict WebView CSP (`connect-src 'none'`) |

---

## Features

- **Full KeePassXC / KeePassDX Interoperability**: Create new `.kdbx` vaults or open/edit existing KDBX 4 / 4.1 databases.
- **Vault Organization**: Hierarchical groups/folders, instant local search, favorites, tags, expiration dates, password history with restore, and custom protected fields.
- **Offline TOTP 2FA Authenticator**: Integrated RFC 6238 (`SHA1` / `SHA256` / `SHA512`, `otpauth://` and KeePassDX `TimeOtp-Secret-Base32`) with live countdown ring.
- **CSPRNG & Diceware Generator**: OS CSPRNG (`OsRng`) unbiased password & 520-word Diceware passphrase generator with Classical + Post-Quantum (Grover) entropy meter.
- **Offline Security Audit**: Detects weak passwords, reused passwords (via in-memory SHA-256 grouping), expired credentials, and KDF floor compliance.
- **Session Hardening**: Inactivity auto-lock watchdog (zeroizes RAM) and automatic clipboard clearing (15s / 30s / 60s).
- **Obsidian / Neon Cyber UI**: Responsive 3-pane desktop layout + adaptive mobile bottom-tab navigation.

---

## Repository Structure

```text
CipherPassX/
├── crates/cipherpass-core/   # Pure-Rust KDBX 4 / 4.1 crypto, XML, TOTP, generator, audit
├── src-tauri/                # Tauri 2 desktop + mobile backend (#![forbid(unsafe_code)])
├── src/                      # React + TypeScript + Tailwind v4 Obsidian/Neon Cyber UI
├── .github/workflows/        # CI (tests/clippy) & Multiplatform Release (.deb/.AppImage/.exe/.apk/.ipa)
└── LICENSE                   # Proprietary — All Rights Reserved (Private Personal Use)
```

---

## Development & Testing

### 1. Run Pure-Rust KDBX 4 Interoperability & Tamper Tests
```bash
cargo test -p cipherpass-core -- --nocapture
cargo clippy -p cipherpass-core --all-targets -- -D warnings
```

### 2. Build Frontend
```bash
npm ci
npm run typecheck
npm run build
```

### 3. Run / Build Tauri 2 Desktop & Mobile
```bash
# Desktop dev
npm run tauri dev

# Desktop production bundles (.deb/.AppImage on Linux, .exe on Windows)
npm run tauri build

# Android (.apk)
npx tauri android init
npx tauri android build --apk

# iOS (.ipa)
npx tauri ios init
npx tauri ios build
```

---

## License

**All Rights Reserved — Private Personal Use.** See [LICENSE](LICENSE).
