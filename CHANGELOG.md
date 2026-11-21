# Changelog

## [0.3.0] - 2026-11-21

### Added

- Daily vulnerability scans for both published images, with GitHub issue tracking
  and advisory links.
- Daily fresh-image scans for fixable vulnerabilities.
- Local image build and Trivy scan scripts, plus container smoke tests in CI.

### Changed

- Install LAM 9.7 from the verified upstream Debian package on Debian Trixie slim.
- Use the Debian Backports libcurl package and standalone tmpfiles in the LAM image.
- Default LAM deployments to a locally built image.
- Remove unused `mount` and `procps` packages from the OpenLDAP image.

### Fixed

- Restore LAM's packaged language list when it is missing from persistent configuration.
- Update the custom `groupOfNames` module for LAM 9.7 compatibility.

## [0.2.1] - 2026-11-15

### Added

- Restricted access to Samba password attributes to the services bind account and LDAP administrator.

## [0.2.0] - 2026-10-27

### Added

#### SSSD Client Integration
- SSSD client deployment with LDAP authentication and TLS.
- LDAP service accounts and access controls for client lookups.

#### Security & CI
- Trivy container scanning and GitHub code-scanning reports.
- Ansible/YAML linting and Renovate dependency updates.

### Changed

- Samba bootstrap generates secure SIDs and defaults to `EMBTOM`.
- Deployments use the latest image tag.
- Updated CI dependencies and base images.

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
