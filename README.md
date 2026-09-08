# OpenLDAP Infrastructure

This repository builds an OpenLDAP container on Debian Trixie and deploys it as
a rootless Podman Quadlet managed by a systemd user service.

## Build the image

```sh
ansible-playbook -i ansible/inventories/hosts.yml \
  ansible/playbooks/openldap_setup.yml
```

## Deploy with Ansible

Install the required collection, set the administrator password in inventory
(preferably through Ansible Vault), then run the playbook:

```sh
ansible-galaxy collection install -r ansible/requirements.yml
ansible-playbook -i inventory.yml ansible/playbooks/openldap_setup.yml \
  -e openldap_config_admin_password='use-a-secret-manager-or-vault'
```

By default, the `openldap_service` role builds `localhost/openldap:trixie` on
the Ansible controller, exports it, and loads it into `openldap`'s
rootless Podman storage on the target host. The generated Quadlet uses
`Pull=never`. To pull an image from a registry instead, set
`openldap_service_container_method: image-pull` and
`openldap_service_image` in inventory; the Quadlet then uses `Pull=always`.

Persistent LDAP data is stored at `/var/lib/openldap/data`. The
`openldap_config` role prepares the initial base entry and `cn=admin` account
from `openldap_config_base_dn`, `openldap_config_organization`, and
`openldap_config_admin_password`; the container imports this data only on its
first start.

The `openldap_config` role generates the `slapd.conf` consumed by the
container. It configures the database, base DN, administrator credentials,
standard schemas, TLS, and custom-schema include path.

## Custom schemas

Declare custom schema files with the `openldap_schema` role in inventory.
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

Set `openldap_config_tls_enabled: true` and provide the certificate and key at
`openldap_service_tls_cert_file` and `openldap_service_tls_key_file` to publish
LDAPS on port 636. The service role permits its rootless service user to bind
ports from 389 onward through `net.ipv4.ip_unprivileged_port_start`.
