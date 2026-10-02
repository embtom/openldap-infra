#!/usr/bin/env python3
"""Interactively configure the SSSD client LDAP endpoint."""

import getpass
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPOSITORY_DIR = Path(
    subprocess.run(
        ["git", "-C", Path(__file__).resolve().parent, "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
)
INVENTORY_VARIABLES_DIR = REPOSITORY_DIR / "ansible/inventories/group_vars/all"
CONFIG_FILE = INVENTORY_VARIABLES_DIR / "sssd-client.yml"


def confirm(prompt: str) -> bool:
    return input(f"{prompt} [y/N] ").lower() in {"y", "yes"}


def read_ldap_host() -> str:
    value = input(
        "LDAP server hostname (must match the LDAPS certificate, e.g. "
        "ldap.example.org): "
    ).strip()
    if not value:
        raise ValueError("LDAP server hostname must not be empty.")
    return value


def read_setting(label: str, default: str) -> str:
    value = input(f"{label} [{default}]: ").strip()
    return value or default


def write_file_atomically(path: Path, content: str, mode: int) -> None:
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as temporary_file:
        temporary_path = Path(temporary_file.name)
        temporary_file.write(content)
    try:
        temporary_path.chmod(mode)
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def main() -> int:
    if CONFIG_FILE.exists() and not confirm(
        "Replace existing local SSSD client configuration?"
    ):
        print("Aborted.")
        return 0

    print(
        "The LDAP server hostname must be a real DNS name that resolves "
        "from this client and matches the Subject/SAN of the LDAPS "
        "certificate. This works whether OpenLDAP runs on this same host "
        "or on a remote host; do not use the 'openldap' Podman-network "
        "alias here, and do not use 'host-gateway'."
    )
    try:
        ldap_host = read_ldap_host()
        search_base = read_setting("LDAP search base", "dc=embtom,dc=org")
        bind_dn = read_setting(
            "LDAP bind DN", f"cn=services-bind,ou=Services,{search_base}"
        )
        bind_password = getpass.getpass("LDAP bind password: ")
        if not bind_password:
            raise ValueError("LDAP bind password must not be empty.")
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    configuration = {
        "sssd_client_ldap_host": ldap_host,
        "sssd_client_search_base": search_base,
        "sssd_client_bind_dn": bind_dn,
        "sssd_client_bind_password": bind_password,
    }
    INVENTORY_VARIABLES_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_file_atomically(
        CONFIG_FILE, f"---\n{json.dumps(configuration, indent=2)}\n", 0o600
    )

    print(f"Created local SSSD client configuration: {CONFIG_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
