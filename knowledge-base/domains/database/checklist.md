# Database Security Checklist

Based on CIS Benchmarks for MongoDB 7.x, PostgreSQL 16, MySQL 8.x, Redis 7.x, and OWASP Database Security Cheat Sheet.

---

## Injection Prevention

- [ ] **DB-INJECT-001** | CRITICAL | NoSQL operator injection: verify all MongoDB queries use sanitized input, not raw `req.body` objects
- [ ] **DB-INJECT-002** | CRITICAL | SQL injection: confirm all SQL queries use parameterized statements, never string concatenation with user input
- [ ] Validate and cast all user inputs to expected types before passing to database queries
- [ ] Use an ORM or query builder that handles escaping automatically (Mongoose, Sequelize, Knex, SQLAlchemy)
- [ ] Implement input length limits and character whitelists for query parameters
- [ ] Disable server-side JavaScript execution in MongoDB (`$where`, `mapReduce`) unless explicitly required

## Authentication & Access Control

- [ ] **DB-AUTH-001** | CRITICAL | Default credentials: verify no connection strings contain default/hardcoded passwords
- [ ] **DB-AUTH-002** | HIGH | Authentication disabled: confirm all database instances require authentication
- [ ] **DB-ACCESS-001** | HIGH | Overly permissive grants: verify no `GRANT ALL ON *.*` or `WITH GRANT OPTION` for application accounts
- [ ] Use dedicated database accounts per service with minimum required permissions
- [ ] Implement password complexity requirements (minimum 16 characters, mixed case, numbers, symbols)
- [ ] Rotate database credentials at least every 90 days
- [ ] Disable or rename default administrative accounts (root, sa, postgres)
- [ ] Use SCRAM-SHA-256 or x.509 certificates for MongoDB authentication
- [ ] Configure `pg_hba.conf` with scram-sha-256, never trust or md5

## Encryption

- [ ] **DB-ENCRYPT-001** | HIGH | Encryption disabled: verify TLS/SSL is enabled for all database connections
- [ ] Enable encryption at rest using database-native features or filesystem encryption (LUKS, dm-crypt)
- [ ] Use TLS 1.2+ with strong cipher suites for all client-to-server and replication connections
- [ ] Deploy certificates signed by a trusted CA, avoid self-signed certificates in production
- [ ] Enable certificate verification on client connections (sslmode=verify-full, --tlsCAFile)
- [ ] Encrypt sensitive fields at the application level before storing (PII, credentials, tokens)

## Network Exposure

- [ ] **DB-EXPOSE-001** | HIGH | Database bound to 0.0.0.0: verify databases bind to localhost or private IPs only
- [ ] Place database servers in private subnets with no direct internet access
- [ ] Use security groups or firewall rules to restrict access to authorized application servers
- [ ] Disable remote administration access; use SSH tunnels or VPN for maintenance
- [ ] Change default database ports (27017, 5432, 3306, 6379) to non-standard ports
- [ ] Enable audit logging for all connection attempts (successful and failed)

## Backup & Recovery

- [ ] **DB-BACKUP-001** | MEDIUM | Unencrypted backups: verify all backup operations encrypt output with GPG, KMS, or equivalent
- [ ] Store backups in encrypted storage with restricted access (separate credentials from production)
- [ ] Test backup restoration procedures at least quarterly
- [ ] Implement backup retention policies (minimum 30 days, maximum per compliance requirements)
- [ ] Transfer backups over encrypted channels only (TLS, SSH, VPN)
- [ ] Maintain backup integrity checksums and verify them before restoration
- [ ] Store backups in a geographically separate location from production data

## Monitoring & Auditing

- [ ] Enable database audit logging for DDL operations (CREATE, ALTER, DROP)
- [ ] Enable audit logging for privilege changes (GRANT, REVOKE)
- [ ] Monitor and alert on failed authentication attempts (threshold: 5 failures in 5 minutes)
- [ ] Monitor and alert on unusual query patterns (large data exports, schema enumeration)
- [ ] Log all administrative operations with user identity and timestamp
- [ ] Forward database logs to a centralized SIEM for correlation and retention
- [ ] Review database access logs weekly for unauthorized or suspicious activity
