#!/bin/sh
set -eu

config_file=/etc/ldap/slapd.d/slapd.conf
bootstrap_file=/etc/ldap/slapd.d/bootstrap.ldif
gitlab_bootstrap_file=/etc/ldap/slapd.d/gitlab.ldif
database_file=/var/lib/ldap/data.mdb

if [ ! -r "$config_file" ]; then
  echo "OpenLDAP configuration is not readable: $config_file" >&2
  exit 1
fi

if [ ! -r "$bootstrap_file" ]; then
  echo "OpenLDAP bootstrap data is not readable: $bootstrap_file" >&2
  exit 1
fi

if [ ! -f "$database_file" ]; then
  echo "Initializing OpenLDAP database from bootstrap LDIF."
  slapadd -f "$config_file" -n 1 -l "$bootstrap_file"
  if [ -s "$gitlab_bootstrap_file" ]; then
    echo "Importing GitLab bootstrap LDIF."
    slapadd -f "$config_file" -n 1 -l "$gitlab_bootstrap_file"
  fi
else
  echo "Using existing OpenLDAP database."
fi

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

slapd_urls="ldap:///"
if grep -q '^TLSCertificateFile ' "$config_file"; then
  slapd_urls="$slapd_urls ldaps:///"
fi

echo "Starting OpenLDAP with listeners: $slapd_urls"
exec slapd -d 0 -f "$config_file" -h "$slapd_urls"
