# OpenLDAP Infrastructure

This repository builds an OpenLDAP container on Debian Trixie and deploys it as
a rootless Podman Quadlet managed by a systemd user service.

[![CI](https://github.com/embtom/openldap-infra/actions/workflows/ci.yml/badge.svg)](https://github.com/embtom/openldap-infra/actions/workflows/ci.yml)

## Build the Image

```sh
ansible-playbook -i ansible/inventories/hosts.yml \
  ansible/playbooks/openldap_setup.yml
```

## Deploy with Ansible

Install the required collection, set the administrator password in the inventory
(preferably through Ansible Vault), then run the playbook:

```sh
ansible-galaxy collection install -r ansible/requirements.yml
ansible-playbook -i inventory.yml ansible/playbooks/openldap_setup.yml \
  -e openldap_config_admin_password='use-a-secret-manager-or-vault'
```

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

Persistent LDAP data is stored at `/var/lib/openldap/data`. The
`openldap_config` role prepares the initial base entry and `cn=admin` account
from `openldap_config_base_dn`, `openldap_config_organization`, and
`openldap_config_admin_password`; the container imports this data only when it
creates a new database.

Changing `openldap_config_base_dn` does not migrate a persistent directory.
Before changing the suffix on an existing deployment, export and back up the
directory, update every DN and DN-valued attribute for the new suffix, then
import the transformed LDIF into a new empty data directory. For disposable
development data, use `scripts/purge-openldap` and deploy again instead. Do
not change the suffix and restart an existing database: OpenLDAP cannot rename
an LDAP tree automatically.

The `openldap_config` role generates the `slapd.conf` consumed by the
container. It configures the database, base DN, administrator credentials,
standard schemas, TLS, and custom-schema include path.

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

Declare custom schema files with the `openldap_schema` role in the inventory.
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

## LDAP Account Manager Networking

OpenLDAP and LDAP Account Manager run on the private rootless Podman bridge
network `ldap-services`. LDAP Account Manager can reach the directory through
the DNS name `openldap` over LDAPS on port `636`; its web interface remains
available through the configured HTTPS host port (default: `8443`).
