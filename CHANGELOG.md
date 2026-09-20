# Changelog

## [0.1.0] - 2026-09-20

### Added

#### Deployment & Architecture
- Rootless Podman Quadlet deployment for OpenLDAP and LDAP Account Manager.
- Container images published and available on GHCR.
- Database-only and complete OpenLDAP recreation options for disposable environments.

#### Security & PKI
- Full LDAPS support with a locally managed root and intermediate PKI.
- Integrated Ansible Vault encryption for all sensitive credentials.

#### LDAP Directory & Integrations
- Bootstrap directory with standard OUs, admin account, and POSIX indexes.
- Optional GitLab LDAP integration with read-only bind account and `memberof` overlay.
- Optional Samba schema and Samba domain bootstrap support.

#### Tooling & DX (Developer Experience)
- Automated LDAP Account Manager (LAM) profile bootstrap.
- Comprehensive deployment helpers, VS Code tasks, linting, and health checks.
