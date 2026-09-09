# Infrastructure PKI

This role creates a root CA, an intermediate issuing CA, and one or more
named server certificates on the Ansible controller. CA private keys remain
on the controller under `~/.local/share/embtom/pki`.

Define every TLS endpoint through `pki_server_certificates`:

```yaml
pki_server_certificates:
  - name: gitlab.example.org
    common_name: gitlab.example.org
    subject_alt_names:
      - DNS:gitlab.example.org
      - DNS:registry.example.org

  - name: ldap.example.org
    common_name: ldap.example.org
    subject_alt_names:
      - DNS:ldap.example.org
      - DNS:ldap
      - IP:192.0.2.10
```

For a request named `ldap.example.org`, the role creates these files:

```text
~/.local/share/embtom/pki/intermediate/private/ldap.example.org.key
~/.local/share/embtom/pki/intermediate/csr/ldap.example.org.csr
~/.local/share/embtom/pki/intermediate/certs/ldap.example.org.crt
~/.local/share/embtom/pki/intermediate/certs/ldap.example.org-fullchain.crt
```

Deploy only the relevant `*.key` and `*-fullchain.crt` to each server. Install
the root CA certificate in clients' trust stores. Do not copy
the root or intermediate CA private key to a service host.

## OpenLDAP

The `openldap_setup.yml` playbook invokes this role automatically when
`openldap_config_tls_enabled: true`. It requests a certificate named after
the host and service, such as `jupiter-openldap`, and deploys its full chain
and private key to the OpenLDAP host. The certificate's common name and DNS
subject alternative name remain `openldap_external_host`.

The playbook derives `openldap_external_host` from the managed host's FQDN,
falling back to its hostname. Set it in inventory only when LDAP clients use a
different DNS name:

```yaml
openldap_config_tls_enabled: true
openldap_external_host: ldap.example.org
```
