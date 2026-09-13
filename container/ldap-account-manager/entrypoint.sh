#!/bin/sh
set -eu

config_dir=/var/lib/ldap-account-manager/config
data_dir=/var/lib/ldap-account-manager/data

mkdir -p "$config_dir" "$data_dir/sess" "$data_dir/tmp/internal"

if [ ! -f "$config_dir/config.cfg" ]; then
  cp /usr/local/share/ldap-account-manager-config.cfg "$config_dir/config.cfg"
fi

if [ ! -f "$config_dir/${LAM_PROFILE_NAME}.conf" ]; then
  cp /usr/local/share/ldap-account-manager-profile.conf \
    "$config_dir/${LAM_PROFILE_NAME}.conf"
fi

/usr/local/bin/ldap-account-manager-bootstrap-profile

chown -R www-data:www-data "$config_dir" "$data_dir"

php-fpm8.4 --nodaemonize &
exec nginx -g 'daemon off;'
