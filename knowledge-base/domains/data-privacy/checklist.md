# Data Privacy Checklist

Based on GDPR, CCPA, ePrivacy Directive, and privacy-by-design principles. Each item maps to a Sentinel rule for automated detection.

---

## PII Protection

- [ ] **PRIV-PII-001** | HIGH | All logging statements are free of raw PII (email, password, SSN) — use masking/redaction utilities
- [ ] **PRIV-PII-002** | HIGH | API responses use DTOs or field projection — never return raw database objects with sensitive fields
- [ ] **PRIV-LOG-001** | HIGH | Credit card numbers, tokens, CVVs, and secrets are never written to application logs
- [ ] Structured logging library is configured with automatic PII field filtering
- [ ] Sensitive fields are enumerated in a deny-list applied at the logging layer
- [ ] Log retention is limited and logs are stored with access controls

## Consent Management

- [ ] **PRIV-CONSENT-001** | HIGH | No tracking scripts (GA, GTM, Facebook Pixel, Hotjar) load before user consent is granted
- [ ] **PRIV-CONSENT-002** | MEDIUM | Non-essential cookies are only set after consent verification
- [ ] A Consent Management Platform (CMP) is integrated and functional
- [ ] Consent records are stored with timestamps, scope, and withdrawal capability
- [ ] Cookie categories are clearly defined: essential, analytics, marketing, functional
- [ ] Scripts use `type="text/plain"` or dynamic loading to prevent execution before consent

## Data Retention & Rights

- [ ] **PRIV-RETAIN-001** | MEDIUM | User data collections have TTL indexes, expiration policies, or scheduled cleanup jobs
- [ ] **PRIV-GDPR-001** | HIGH | A DELETE endpoint or data erasure mechanism exists for user/account data
- [ ] Data retention periods are documented and enforced for each data category
- [ ] Right to access (GDPR Art. 15): users can export their personal data
- [ ] Right to rectification (GDPR Art. 16): users can update their personal data
- [ ] Right to erasure (GDPR Art. 17): cascading deletion covers all storage systems (DB, cache, backups, logs)
- [ ] Right to portability (GDPR Art. 20): data export is available in machine-readable format (JSON/CSV)
- [ ] Anonymization or pseudonymization is applied to data retained for analytics after the retention period

## Cross-Border Transfer

- [ ] **PRIV-TRANS-001** | HIGH | Personal data sent to external APIs uses encryption in transit (TLS 1.2+)
- [ ] Data Processing Agreements (DPAs) with Standard Contractual Clauses (SCCs) are signed with all third-party processors
- [ ] Transfer Impact Assessments (TIAs) are completed for transfers outside the EU/EEA
- [ ] Third-party sub-processors are documented and reviewed annually
- [ ] Data residency requirements are identified and enforced per jurisdiction

## General Privacy-by-Design

- [ ] Privacy Impact Assessment (PIA/DPIA) is conducted for new features handling personal data
- [ ] Data minimization: only necessary personal data is collected for each purpose
- [ ] Purpose limitation: data is used only for the purpose it was collected for
- [ ] Access controls enforce least-privilege on personal data stores
- [ ] Breach notification procedures are documented and tested (72-hour GDPR requirement)
- [ ] Privacy policy is up to date and accurately reflects data processing activities
