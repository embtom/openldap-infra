#!/bin/sh
set -eu

config_file=/etc/ldap/slapd.d/slapd.conf
bootstrap_file=/etc/ldap/slapd.d/bootstrap.ldif

if [ ! -r "$config_file" ]; then
  echo "OpenLDAP configuration is not readable: $config_file" >&2
  exit 1
fi

if [ ! -r "$bootstrap_file" ]; then
  echo "OpenLDAP bootstrap data is not readable: $bootstrap_file" >&2
  exit 1
fi

bootstrap_base_dn=$(sed -n 's/^dn: //p' "$bootstrap_file" | head -n 1)
if [ -z "$bootstrap_base_dn" ]; then
  echo "OpenLDAP bootstrap data does not define a base DN." >&2
  exit 1
fi

if ! slapcat -f "$config_file" -b "$bootstrap_base_dn" 2>/dev/null |
  grep -q "^dn: $bootstrap_base_dn$"; then
  slapadd -f "$config_file" -n 1 -l "$bootstrap_file"
fi

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

slapd_urls="ldap:///"
if grep -q '^TLSCertificateFile ' "$config_file"; then
  slapd_urls="$slapd_urls ldaps:///"
fi

exec slapd -d 0 -f "$config_file" -h "$slapd_urls"
