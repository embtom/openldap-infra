# OpenLDAP Infrastructure

This repository builds an OpenLDAP container on Debian Trixie and deploys it as
a rootless Podman Quadlet managed by a systemd user service.

[![CI](https://github.com/embtom/openldap-infra/actions/workflows/ci.yml/badge.svg)](https://github.com/embtom/openldap-infra/actions/workflows/ci.yml)

## VS Code Tasks

Run `Tasks: Run Task` from the Command Palette, then choose an `ansible:` task.
Tasks that deploy prompt for the SSH host (default: `localhost`); the tagged
deployment also prompts for `openldap`, `config`, `service`, or
`ldap-account-manager`.

| Task | Command | Use |
| --- | --- | --- |
| `ansible: install` | `scripts/install-requirements && scripts/install-ansible` | Install the Python and Ansible dependencies once. |
| `ansible: lint` | `scripts/ansible-lint` | Check the Ansible code before deployment. |
| `ansible: configure OpenLDAP` | `python3 scripts/configure-openldap.py` | Create the local configuration and encrypted Vault. Run before the first deployment. |
| `ansible: run all roles` | `scripts/deploy --host <host>` | Build or obtain images, configure OpenLDAP, and start all enabled services. |
| `ansible: run by tag` | `scripts/deploy --host <host> --tag <tag>` | Deploy only one area while iterating. |
| `ansible: recreate OpenLDAP database` | `scripts/deploy --host <host> --tag config,service --recreate-data` | Delete only LDAP data, then initialize a fresh database. Destructive. |
| `ansible: fully recreate OpenLDAP` | `scripts/deploy --host <host> --tag config,service --recreate-all` | Delete LDAP data, generated configuration, and schemas before redeploying. Destructive. |

The configuration task asks whether to enable GitLab LDAP authentication. It
writes non-secret settings to `ansible/inventories/group_vars/all/config.yml`
and passwords to the encrypted, Git-ignored
`ansible/inventories/group_vars/all/vault.yml`. Deployments prompt for the
Vault and sudo passwords; LDAP passwords are never command-line arguments.

By default, the `openldap_service` and `ldap_account_manager` roles pull their
published GHCR images. The generated Quadlets use `Pull=always`:

```yaml
openldap_service_container_method: image-pull
ldap_account_manager_container_method: image-pull
```

The roles use `ghcr.io/embtom/openldap-infra/openldap:latest` and
`ghcr.io/embtom/openldap-infra/ldap-account-manager:latest` by default.
Override either role's `*_image_pull_image` value to use another registry image.

To build from the local checkout instead, set either role's
`*_container_method` to `direct-build`. The image is then built on the Ansible
controller, transferred into the service user's rootless Podman storage, and
the Quadlet uses `Pull=never`.

OpenLDAP data lives in `/var/lib/openldap/data`; bootstrap entries are imported
only for a new database. A changed `openldap_config_base_dn` requires an LDAP
data migration, not a restart. Export and transform all DN-valued data before
importing it into a new directory. For disposable data, use the database-reset
task above. The complete-reset task additionally removes generated
configuration and schemas; TLS material and the service user remain.

## GitLab LDAP Authentication

GitLab access is controlled with a dedicated `groupOfNames` group. The
`memberof` overlay adds a computed `memberOf` attribute to users listed in a
group, which GitLab uses in its LDAP user filter.

GitLab LDAP integration is disabled by default. The configuration script can
enable it, or set these inventory variables explicitly before initializing a
new directory:

```yaml
openldap_config_gitlab:
  enabled: true
  memberof_enabled: true
```

The GitLab bind password is stored in the local Ansible Vault as
`openldap_config_gitlab_bind_password`.

This creates the following entries under the configured base DN:

```text
cn=gitlab-bind,ou=Services,<base DN>
cn=gitlab-users,ou=Groups,<base DN>
```

`gitlab-bind` is the read-only account GitLab uses for LDAP searches. Keep its
password in Ansible Vault or another secret source. `gitlab-users` is the
access group; add each permitted person as a `member`, for example:

```ldif
dn: cn=gitlab-users,ou=Groups,dc=embtom,dc=org
changetype: modify
add: member
member: uid=alice,ou=People,dc=embtom,dc=org
```

The user's resulting `memberOf` value is:

```text
cn=gitlab-users,ou=Groups,dc=embtom,dc=org
```

The GitLab service must use the same bind account, password, group DN, and the
OpenLDAP server's root CA. Configure the corresponding
`gitlab_service_ldap_*` variables in the `gitlab-infra` inventory: enable LDAP,
use the OpenLDAP DNS name on LDAPS port `636`, set `simple_tls`, enable
certificate verification, and set
`gitlab_service_ldap_required_group_dn` to the `gitlab-users` DN.

GitLab bootstrap LDIF is imported only when OpenLDAP creates an empty database.
Enabling these values does not alter an existing directory. For an existing
database, create the bind account and group separately, add authorized members,
then enable the `memberof` overlay before deploying GitLab.

## Samba Domain

Samba schema support is enabled by default, but a Samba domain is optional. The
configuration task can bootstrap one for a new database. Provide the domain name
and the domain SID reported by the Samba server with `net getdomainsid`; LAM
then uses the `sambaDomain` entry to create Samba users and groups. Enabling
this feature does not modify an existing database.

## Test LDAP

Query the root DSE and verify that the service responds with its configured
base DN:

```sh
./scripts/test-openldap
```

The test connects through LDAPS on port 636 by default and verifies the server
certificate against the PKI root CA at
`~/.local/share/embtom/pki/certs/root-ca.crt`.
For a remote server, non-default port, or root CA stored elsewhere, specify the
target explicitly:

```sh
./scripts/test-openldap --host ldap.example.org --ca-cert /path/to/root-ca.crt
```

To test unencrypted LDAP on port 389, select the LDAP protocol explicitly:

```sh
./scripts/test-openldap --protocol ldap
```

Verify the GitLab LDAP integration, including the bind account, access group,
and users that pass the `memberOf` access filter:

```sh
./scripts/test-gitlab-ldap
```

The script prompts once for the GitLab bind password and does not modify LDAP.

Print the active schema as published by the LDAP server:

```sh
./scripts/test-openldap-schema
```

The script resolves the server's `subschemaSubentry` and prints its active
attribute types, object classes, LDAP syntaxes, and matching rules. It accepts
the same `--host`, `--protocol`, `--port`, and `--ca-cert` options as
`test-openldap`. Pass `--raw` to print the complete schema entry as LDIF.

Show the active Linux/SSSD, person, and Samba capabilities with their
available object classes and attributes:

```sh
./scripts/test-openldap-enabled-schemas
```

## LDAP Account Manager

The deployment also builds and runs LDAP Account Manager as a separate,
rootless Podman Quadlet service. Its locally built image tag is
`localhost/ldap-account-manager:trixie`, and the web interface is available
on port `8443` by default.

```text
https://localhost:8443/
```

LAM configuration and runtime data persist under `/var/lib/ldap-account-manager`.
Set `ldap_account_manager_enabled: false` to skip this service, or override
`ldap_account_manager_https_port` for a different HTTPS host port.

LAM connects to OpenLDAP using verified LDAPS on the private `ldap-services`
network. The OpenLDAP certificate includes the internal `openldap` DNS alias,
and the LAM role installs the deployment root CA in its persistent
configuration directory.

LAM writes application logs to `/var/lib/ldap-account-manager/data/lam.log`. Its entrypoint
forwards new log lines to standard error, which Podman captures in the system
journal. View them with `sudo journalctl CONTAINER_NAME=lam`.

Test an authenticated administrator bind and list the configured directory:

```sh
./scripts/test-openldap-admin
```

The script prompts for the administrator password. Use `--base-dn` when the
deployment does not use the default `dc=embtom,dc=org` base DN.

## Directory Structure

The initial directory uses `dc=embtom,dc=org` and creates these organizational
units:

```text
ou=People
ou=Groups
ou=Services
ou=Computers
ou=Samba
```

The configuration includes indexes for POSIX accounts and groups. The initial
access controls permit password authentication for
anonymous clients, password changes by account owners, and directory reads by
authenticated users. The LDAP administrator has full access.

## Custom Schemas

Declare custom schema files with the `openldap_config` role in the inventory.
Ansible writes them to
`/var/lib/openldap/schema`, and the Quadlet mounts that directory read-only at
`/etc/ldap/custom-schema`. The generated `slapd.conf` includes every
`*.schema` file there.

```yaml
openldap_config_schemas:
  - filename: example.schema
    content: |
      attributetype ( 1.3.6.1.4.1.99999.1.1
        NAME 'exampleIdentifier'
        DESC 'Example identifier'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
```

To publish LDAPS on port 636, enable TLS and set the DNS name clients use to
reach the LDAP server:

```yaml
openldap_config_tls_enabled: true
openldap_external_host: ldap.example.org
```

The `pki` role creates host- and service-specific TLS artifacts, such as
`ldap.example.org-openldap-fullchain.crt`, on the Ansible controller. The
service role deploys them to the LDAP host and permits its rootless user to
bind ports from 389 onward through
`net.ipv4.ip_unprivileged_port_start`.

## Configuration Reference

Set role variables in inventory or through Ansible Vault. Values shown below
are defaults. Do not store passwords in version control.

### OpenLDAP Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `openldap_config_user` | `openldap` | Linux account that owns OpenLDAP configuration and data. |
| `openldap_config_service_name` | `openldap` | Rootless systemd and container service name. |
| `openldap_config_base_dn` | `dc=embtom,dc=org` | LDAP directory suffix. Changing it is a data migration. |
| `openldap_config_organization` | `embtom` | Organization attribute on the root directory entry. |
| `openldap_config_admin_password` | required | Password for `cn=admin,<base DN>`; generated in the local Vault. |
| `openldap_config_tls_enabled` | `true` | Enables LDAPS listener and TLS configuration. |
| `openldap_config_samba.enabled` | `true` | Includes the Samba schema and Samba-specific indexes. |
| `openldap_config_samba.domain.enabled` | `false` | Creates a `sambaDomain` entry in a new database. Requires a domain name and the Samba server's domain SID. |
| `openldap_config_samba.domain.name` | required when enabled | Samba domain name, for example `EMBTOM`. |
| `openldap_config_samba.domain.sid` | required when enabled | Domain SID reported by `net getdomainsid`. |
| `openldap_config_samba.domain.next_rid` | `1000` | First RID allocated by the Samba domain. |
| `openldap_config_gitlab.enabled` | `false` | Adds GitLab bootstrap entries on a new database; requires `memberof_enabled` and a bind password. |
| `openldap_config_gitlab.memberof_enabled` | `false` | Enables the `memberof` overlay, which derives each entry's `memberOf` attribute from group membership. |
| `openldap_config_gitlab.bind_cn` | `gitlab-bind` | CN of the GitLab read-only LDAP bind account. |
| `openldap_config_gitlab.bind_password` | required | Password for the GitLab bind account; generated in the local Vault. |
| `openldap_config_gitlab.access_group` | `gitlab-users` | `groupOfNames` group used to allow GitLab sign-in. |
| `openldap_config_schemas` | `[]` | Extra schemas, each with `filename` and inline `content`. |
| `openldap_config_samba_schema` | `samba.schema` | Schema file list used when Samba support is enabled. |
| `openldap_config_schema_dir` | `/var/lib/openldap/schema` | Destination directory for configured custom schema files. |
| `openldap_config_organizational_units` | `People`, `Groups`, `Services`, `Computers`, `Samba` | Organizational units created in a new database. |
| `openldap_config_indexes` | standard LDAP indexes | Database indexes for general LDAP queries. |
| `openldap_config_samba_indexes` | standard Samba indexes | Extra indexes added when Samba support is enabled. |
| `openldap_config_dir` | `/var/lib/openldap/config` | Persistent host directory for generated configuration and bootstrap LDIF files. |
| `openldap_config_file` | `<config dir>/slapd.conf` | Generated OpenLDAP configuration file. |
| `openldap_config_bootstrap_file` | `<config dir>/bootstrap.ldif` | Base directory data imported only for an empty database. |
| `openldap_config_gitlab.bootstrap_file` | `<config dir>/gitlab.ldif` | Optional GitLab entries imported only for an empty database. |

### OpenLDAP Service

| Variable | Default | Purpose |
| --- | --- | --- |
| `openldap_service_user` | `openldap_config_user` | Linux user that runs the rootless Podman service. |
| `openldap_service_name` | `openldap_config_service_name` | Quadlet and container name. |
| `openldap_service_container_method` | `image-pull` | Image source: `image-pull` downloads from a registry; `direct-build` builds and transfers locally. |
| `openldap_service_direct_build_image` | `localhost/openldap:trixie` | Image tag used by `direct-build`. |
| `openldap_service_image_pull_image` | `ghcr.io/embtom/openldap-infra/openldap:latest` | Registry image used by `image-pull`. |
| `openldap_service_image` | selected by method | Effective image name; normally do not override it. |
| `openldap_service_containerfile` | `container/openldap/Containerfile` | Containerfile used for local builds. |
| `openldap_service_build_context` | `.` | Build context used for local builds. |
| `openldap_service_build_extra_args` | empty | Additional arguments appended to `podman build`. |
| `openldap_service_force_rebuild` | `false` | Removes the local image before a direct build. |
| `openldap_service_data_dir` | `/var/lib/openldap/data` | Persistent LDAP database directory. |
| `openldap_service_data_recreate` | `false` | Stops OpenLDAP and deletes only the database directory before deployment. The next start imports fresh bootstrap data. Destructive; return it to `false` after one deploy. |
| `openldap_service_full_recreate` | `false` | Stops OpenLDAP and deletes the data, generated configuration, and schema directories before deployment. TLS material and the service user remain. Destructive; return it to `false` after one deploy. |
| `openldap_service_schema_dir` | `/var/lib/openldap/schema` | Host directory containing configured custom schemas. |
| `openldap_service_unprivileged_port_start` | `389` | Lowest port the rootless service user may bind; managed with sysctl. |
| `openldap_service_ldap_port` | `389` | Published unencrypted LDAP port. |
| `openldap_service_ldaps_port` | `636` | Published LDAPS port when TLS is enabled. |
| `openldap_service_tls_enabled` | `openldap_config_tls_enabled` | Enables TLS mounts and LDAPS publication. |
| `openldap_service_tls_dir` | `/var/lib/openldap/tls` | Host directory containing the LDAP certificate and private key. |
| `openldap_service_tls_server_name` | `openldap_external_host` | DNS name placed in the LDAP server certificate. |
| `openldap_service_tls_certificate_name` | `<server name>-<service name>` | PKI artifact prefix for LDAP TLS files. |

### LDAP Account Manager

| Variable | Default | Purpose |
| --- | --- | --- |
| `ldap_account_manager_enabled` | `true` | Deploys LAM when true. |
| `ldap_account_manager_user` | `openldap_service_user` | Linux user that runs the rootless LAM service. |
| `ldap_account_manager_service_name` | `lam` | Quadlet and container name. |
| `ldap_account_manager_container_method` | `image-pull` | Image source: `image-pull` or `direct-build`. |
| `ldap_account_manager_direct_build_image` | `localhost/ldap-account-manager:trixie` | Image tag used by `direct-build`. |
| `ldap_account_manager_image_pull_image` | `ghcr.io/embtom/openldap-infra/ldap-account-manager:latest` | Registry image used by `image-pull`. |
| `ldap_account_manager_image` | selected by method | Effective image name; normally do not override it. |
| `ldap_account_manager_containerfile` | `container/ldap-account-manager/Containerfile` | Containerfile used for local builds. |
| `ldap_account_manager_build_context` | `.` | Build context used for local builds. |
| `ldap_account_manager_build_extra_args` | empty | Additional arguments appended to `podman build`. |
| `ldap_account_manager_force_rebuild` | `false` | Removes the local image before a direct build. |
| `ldap_account_manager_config_dir` | `/var/lib/ldap-account-manager/config` | Persistent LAM configuration directory. |
| `ldap_account_manager_data_dir` | `/var/lib/ldap-account-manager/data` | Persistent LAM sessions, temporary files, and logs. |
| `ldap_account_manager_https_port` | `8443` | Published HTTPS port. |
| `ldap_account_manager_tls_enabled` | `openldap_config_tls_enabled` | Enables the HTTPS certificate mount and published HTTPS port. |
| `ldap_account_manager_tls_dir` | `/var/lib/ldap-account-manager/tls` | Host directory containing the LAM web certificate and private key. |
| `ldap_account_manager_tls_server_name` | `openldap_external_host` | DNS name placed in the LAM HTTPS certificate. |
| `ldap_account_manager_tls_certificate_name` | `<hostname>-lam` | PKI artifact prefix for LAM TLS files. |
| `ldap_account_manager_profile_name` | `openldap` | LAM server-profile name created at startup. |
| `ldap_account_manager_server_url` | `ldaps://openldap:636` | LDAP endpoint used inside the private Podman network. |
| `ldap_account_manager_base_dn` | `openldap_config_base_dn` | Directory suffix configured in the LAM server profile. |
| `ldap_account_manager_ca_certificate` | `pki_root_ca_certificate` | Root CA file LAM trusts for LDAPS. |
| `ldap_account_manager_log_destination` | `/var/lib/ldap-account-manager/data/lam.log` | LAM application log file, forwarded to the container journal. |

### PKI Role

| Variable | Default | Purpose |
| --- | --- | --- |
| `pki_root_ca_common_name` | `embtom Infrastructure Root CA` | Subject CN of the root certificate authority. |
| `pki_country` | `DE` | X.509 subject country for generated certificates. |
| `pki_state` | `Bayern` | X.509 subject state for generated certificates. |
| `pki_organization` | `embtom` | X.509 subject organization for generated certificates. |
| `pki_controller_root_dir` | `~/.local/share/embtom/pki` | Controller-side PKI state directory. Protect and back it up. |
| `pki_root_ca_key` | `<root dir>/private/root-ca.key` | Root CA private key path. |
| `pki_root_ca_csr` | `<root dir>/csr/root-ca.csr` | Root CA certificate-signing request path. |
| `pki_root_ca_certificate` | `<root dir>/certs/root-ca.crt` | Root CA certificate path. |
| `pki_intermediate_ca_common_name` | `embtom Infrastructure Issuing CA` | Subject CN of the issuing CA. |
| `pki_intermediate_ca_dir` | `<root dir>/intermediate` | Controller-side issuing CA state directory. |
| `pki_intermediate_ca_key` | `<intermediate dir>/private/intermediate-ca.key` | Issuing CA private key path. |
| `pki_intermediate_ca_csr` | `<intermediate dir>/csr/intermediate-ca.csr` | Issuing CA certificate-signing request path. |
| `pki_intermediate_ca_certificate` | `<intermediate dir>/certs/intermediate-ca.crt` | Issuing CA certificate path. |
| `pki_server_certificates` | defined by playbook | Certificate request list. Each item requires `name`, `common_name`, and `subject_alt_names`. |

## LDAP Account Manager Networking

OpenLDAP and LDAP Account Manager run on the private rootless Podman bridge
network `ldap-services`. LDAP Account Manager can reach the directory through
the DNS name `openldap` over LDAPS on port `636`; its web interface remains
available through the configured HTTPS host port (default: `8443`).
