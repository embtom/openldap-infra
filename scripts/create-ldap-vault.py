#!/usr/bin/env python3
"""Interactively create the local encrypted LDAP secrets vault."""

import argparse
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
VAULT_FILE = REPOSITORY_DIR / "ansible/inventories/group_vars/all/vault.yml"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create or replace the local encrypted LDAP secrets vault. "
            "The script prompts for the LDAP administrator password, GitLab "
            "bind password, and Ansible Vault password."
        )
    )
    return parser.parse_args()


def read_secret(label: str) -> str:
    password = getpass.getpass(f"{label}: ")
    confirmation = getpass.getpass(f"Confirm {label.lower()}: ")
    if not password:
        raise ValueError("Password must not be empty.")
    if password != confirmation:
        raise ValueError("Passwords do not match.")
    return password


def confirm_replacement() -> bool:
    answer = input(f"Replace existing LDAP secrets vault '{VAULT_FILE}'? [y/N] ")
    return answer.lower() in {"y", "yes"}


def main() -> int:
    parse_arguments()
    if shutil.which("ansible-vault") is None:
        print("ERROR: ansible-vault is not installed or not in PATH.", file=sys.stderr)
        return 1
    if VAULT_FILE.exists() and not confirm_replacement():
        print("Aborted.")
        return 0

    try:
        secrets = {
            "openldap_config_admin_password": read_secret(
                "LDAP administrator password"
            ),
            "openldap_config_gitlab_bind_password": read_secret("GitLab bind password"),
        }
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    VAULT_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=VAULT_FILE.parent, delete=False
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
        VAULT_FILE.chmod(0o600)
    finally:
        temporary_path.unlink(missing_ok=True)
        encrypted_path.unlink(missing_ok=True)

    print(f"Created encrypted LDAP secrets vault: {VAULT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
