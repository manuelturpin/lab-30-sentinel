# Infrastructure Security Checklist

Based on CIS Benchmarks (Docker, Kubernetes, AWS/GCP/Azure), NIST SP 800-190 (Container Security), and cloud security best practices.

---

## Docker

- [ ] **INFRA-DOCKER-001** | HIGH (7.5) | Verify all Dockerfiles use a non-root USER before ENTRYPOINT/CMD
- [ ] **INFRA-DOCKER-002** | MEDIUM (5.3) | Ensure no secrets are passed via ARG instructions; use BuildKit secret mounts
- [ ] **INFRA-DOCKER-003** | MEDIUM (5.5) | Pin all base images to specific version tags or SHA256 digests; no :latest
- [ ] Scan images for known CVEs using Trivy, Grype, or Snyk Container before deployment
- [ ] Use multi-stage builds to minimize final image attack surface
- [ ] Set HEALTHCHECK instructions for container orchestration reliability
- [ ] Use COPY instead of ADD for local file operations
- [ ] Ensure .dockerignore excludes secrets, .git, and unnecessary files

## Kubernetes

- [ ] **INFRA-K8S-001** | CRITICAL (9.0) | No containers running in privileged mode; enforce via PodSecurityAdmission
- [ ] **INFRA-K8S-002** | HIGH (7.8) | hostNetwork disabled on all application pods
- [ ] **INFRA-K8S-003** | MEDIUM (5.5) | Resource requests and limits defined on every container; LimitRange in each namespace
- [ ] Set automountServiceAccountToken: false on pods that do not need API access
- [ ] Deploy workloads in dedicated namespaces, never in default
- [ ] Apply NetworkPolicies to restrict pod-to-pod communication (default deny ingress/egress)
- [ ] Enable PodSecurityAdmission with restricted profile on production namespaces
- [ ] Use read-only root filesystem where possible (readOnlyRootFilesystem: true)
- [ ] Run containers with allowPrivilegeEscalation: false
- [ ] Regularly audit RBAC roles for excessive permissions (no cluster-admin for workloads)

## Secrets Management

- [ ] **INFRA-SECRET-001** | CRITICAL (9.2) | No plaintext secrets in environment variable declarations (compose/k8s/CI)
- [ ] Ensure .env files are in .gitignore and never committed to the repository
- [ ] Use external secrets managers (Vault, AWS Secrets Manager, GCP Secret Manager)
- [ ] Terraform sensitive variables have no default values and are marked sensitive = true
- [ ] Rotate all secrets on a defined schedule (90 days max for production credentials)
- [ ] Use sealed-secrets or external-secrets-operator for Kubernetes secret management
- [ ] Audit git history for accidentally committed secrets (use git-secrets, truffleHog, or gitleaks)

## TLS / Network / IAM

- [ ] **INFRA-TLS-001** | HIGH (8.2) | TLS certificate verification enabled in all HTTP clients and SDK configurations
- [ ] **INFRA-IAM-001** | CRITICAL (9.4) | No wildcard (*) Action or Resource in IAM policies; follow least privilege
- [ ] **INFRA-NET-001** | HIGH (7.4) | No security group rules allowing ingress from 0.0.0.0/0 except for public-facing load balancers
- [ ] Enforce TLS 1.2+ minimum on all endpoints; disable SSLv3, TLS 1.0, TLS 1.1
- [ ] Use certificate pinning for critical internal service-to-service communication
- [ ] Enable VPC Flow Logs / Cloud Audit Logs for network traffic monitoring
- [ ] Use VPN or bastion hosts for administrative access; no direct SSH from internet
- [ ] Apply WAF rules on public-facing load balancers and API gateways
- [ ] Enable MFA on all IAM accounts with console access
- [ ] Review and remove unused IAM roles, users, and access keys quarterly
