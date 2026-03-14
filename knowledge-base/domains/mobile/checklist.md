# Mobile Security Checklist

Based on OWASP Mobile Top 10 2024. Use this checklist during code reviews and security assessments of mobile applications (iOS, Android, React Native, Flutter).

## M01:2024 — Improper Credential Usage
- [ ] **MOB-CRED-001** | CRITICAL | No hardcoded credentials (API keys, passwords, secrets) in source code
- [ ] **MOB-CRED-002** | HIGH | Credentials stored in secure keystore (Android) or keychain (iOS), not in SharedPreferences/NSUserDefaults

## M02:2024 — Inadequate Supply Chain Security
- [ ] **MOB-SUPPLY-001** | HIGH | All third-party SDKs and dependencies use pinned versions with integrity verification

## M03:2024 — Insecure Authentication/Authorization
- [ ] **MOB-AUTH-001** | HIGH | Biometric authentication is cryptographically bound (CryptoObject on Android, Keychain access control on iOS), not event-based

## M04:2024 — Insufficient Input/Output Validation
- [ ] **MOB-VALID-001** | HIGH | All deep link and universal link parameters are validated and sanitized before processing

## M05:2024 — Insecure Communication
- [ ] **MOB-COMM-001** | HIGH | Certificate pinning is implemented for all API connections; no disabled TLS verification or hostname checking

## M06:2024 — Inadequate Privacy Controls
- [ ] **MOB-PRIV-001** | MEDIUM | Data collection is minimized to app requirements; consent is obtained before accessing device identifiers, location, or contacts

## M07:2024 — Insufficient Binary Protections
- [ ] **MOB-BIN-001** | MEDIUM | Code obfuscation (ProGuard/R8) enabled for release builds; root/jailbreak detection implemented

## M08:2024 — Security Misconfiguration
- [ ] **MOB-CONF-001** | HIGH | Debug mode disabled in production; backups restricted or disabled; cleartext traffic not allowed; exported components protected

## M09:2024 — Insecure Data Storage
- [ ] **MOB-STORE-001** | CRITICAL | Sensitive data stored only in encrypted internal storage; no sensitive data on external storage, in logs, or in clipboard

## M10:2024 — Insufficient Cryptography
- [ ] **MOB-CRYPTO-001** | HIGH | Only strong, current cryptographic algorithms used (AES-256-GCM, SHA-256+); no MD5, SHA1, DES, RC4, or ECB mode
