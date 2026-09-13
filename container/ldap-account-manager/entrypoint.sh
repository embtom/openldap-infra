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

if [ ! -d "$config_dir/templates" ]; then
  cp -a /usr/local/share/ldap-account-manager-templates "$config_dir/templates"
fi

/usr/local/bin/ldap-account-manager-bootstrap-profile

find -P "$config_dir" "$data_dir" -xdev ! -type l \
  -exec chown www-data:www-data {} +

touch "$LAM_LOG_DESTINATION"
chown www-data:www-data "$LAM_LOG_DESTINATION"
tail -n 0 -F "$LAM_LOG_DESTINATION" >&2 &

php-fpm8.4 --nodaemonize &
exec nginx -g 'daemon off;'
