#!/usr/bin/env python3
"""Interactively configure local OpenLDAP settings and secrets."""

import getpass
import json
import shutil
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
CONFIG_FILE = INVENTORY_VARIABLES_DIR / "config.yml"
VAULT_FILE = INVENTORY_VARIABLES_DIR / "vault.yml"


def read_secret(label: str) -> str:
    password = getpass.getpass(f"{label}: ")
    confirmation = getpass.getpass(f"Confirm {label.lower()}: ")
    if not password:
        raise ValueError("Password must not be empty.")
    if password != confirmation:
        raise ValueError("Passwords do not match.")
    return password


def confirm(prompt: str) -> bool:
    return input(f"{prompt} [y/N] ").lower() in {"y", "yes"}


def read_samba_domain_setting(label: str) -> str:
    value = input(f"{label}: ").strip()
    if not value:
        raise ValueError(f"{label} must not be empty.")
    return value


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


def encrypt_vault(secrets: dict[str, str]) -> None:
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=INVENTORY_VARIABLES_DIR, delete=False
    ) as temporary_file:
        temporary_path = Path(temporary_file.name)
        temporary_file.write(json.dumps(secrets, indent=2))
        temporary_file.write("\n")
    encrypted_path = temporary_path.with_name(f"{temporary_path.name}.vault")

    try:
        temporary_path.chmod(0o600)
        subprocess.run(
            [
                "ansible-vault",
                "encrypt",
                "--output",
                str(encrypted_path),
                str(temporary_path),
            ],
            check=True,
        )
        encrypted_path.chmod(0o600)
        encrypted_path.replace(VAULT_FILE)
    finally:
        temporary_path.unlink(missing_ok=True)
        encrypted_path.unlink(missing_ok=True)


def main() -> int:
    if shutil.which("ansible-vault") is None:
        print("ERROR: ansible-vault is not installed or not in PATH.", file=sys.stderr)
        return 1
    if (CONFIG_FILE.exists() or VAULT_FILE.exists()) and not confirm(
        "Replace existing local OpenLDAP configuration and secrets vault?"
    ):
        print("Aborted.")
        return 0

    gitlab_enabled = confirm("Enable GitLab LDAP authentication?")
    samba_domain_enabled = confirm("Bootstrap a Samba domain for LAM?")
    try:
        secrets = {
            "openldap_config_admin_password": read_secret("LDAP administrator password")
        }
        if gitlab_enabled:
            secrets["openldap_config_gitlab_bind_password"] = read_secret(
                "GitLab bind password"
            )
        samba_domain = {}
        if samba_domain_enabled:
            samba_domain = {
                "name": read_samba_domain_setting("Samba domain name"),
                "sid": read_samba_domain_setting("Samba domain SID"),
            }
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    configuration = {
        "openldap_config_gitlab": {
            "enabled": gitlab_enabled,
            "memberof_enabled": gitlab_enabled,
            "bind_cn": "gitlab-bind",
            "bind_password": "{{ openldap_config_gitlab_bind_password | default('') }}",
            "access_group": "gitlab-users",
            "bootstrap_file": "{{ openldap_config_dir }}/gitlab.ldif",
        },
    }
    configuration["openldap_config_samba"] = {
        "enabled": True,
        "domain": {
            "enabled": samba_domain_enabled,
            "name": "",
            "sid": "",
            "next_rid": 1000,
            "bootstrap_file": "{{ openldap_config_dir }}/samba-domain.ldif",
            **samba_domain,
        },
    }
    INVENTORY_VARIABLES_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_file_atomically(
        CONFIG_FILE, f"---\n{json.dumps(configuration, indent=2)}\n", 0o600
    )
    encrypt_vault(secrets)

    print(f"Created local OpenLDAP configuration: {CONFIG_FILE}")
    print(f"Created encrypted LDAP secrets vault: {VAULT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
