#!/usr/bin/env python3
"""Print schema definitions published by an OpenLDAP server."""

from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CA_CERT = Path.home() / ".local/share/embtom/pki/certs/root-ca.crt"


@dataclass(frozen=True)
class SchemaDefinition:
    category: str
    name: str
    oid: str


def parse_arguments(default_view: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspect the schema published by an LDAP server."
    )
    parser.add_argument("-H", "--host", default=socket.getfqdn())
    parser.add_argument("-P", "--protocol", choices=("ldap", "ldaps"), default="ldaps")
    parser.add_argument("-p", "--port", type=int)
    parser.add_argument("-c", "--ca-cert", type=Path, default=DEFAULT_CA_CERT)
    parser.add_argument(
        "--raw", action="store_true", help="print the complete schema entry as raw LDIF"
    )
    parser.set_defaults(view=default_view)
    return parser.parse_args()


def ldapsearch(
    arguments: argparse.Namespace, base: str, scope: str, attributes: Iterable[str]
) -> str:
    port = arguments.port or (636 if arguments.protocol == "ldaps" else 389)
    uri = f"{arguments.protocol}://{arguments.host}:{port}"
    command = [
        "ldapsearch",
        "-x",
        "-LLL",
        "-o",
        "ldif-wrap=no",
        "-H",
        uri,
        "-b",
        base,
        "-s",
        scope,
        *attributes,
    ]
    environment = os.environ.copy()
    if arguments.protocol == "ldaps":
        if not arguments.ca_cert.is_file():
            raise ValueError(
                f"Root CA certificate '{arguments.ca_cert}' does not exist."
            )
        environment["LDAPTLS_CACERT"] = str(arguments.ca_cert)
        environment["LDAPTLS_REQCERT"] = "demand"

    try:
        result = subprocess.run(
            command, text=True, capture_output=True, env=environment, check=False
        )
    except FileNotFoundError as error:
        raise RuntimeError(
            "ldapsearch is not installed or not available in PATH."
        ) from error
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "ldapsearch failed.")
    return result.stdout


def parse_ldif(text: str) -> dict[str, list[str]]:
    attributes: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition(": ")
        if separator:
            attributes.setdefault(name, []).append(value)
    return attributes


def definition_name(definition: str, category: str) -> str:
    if category == "ldapSyntaxes":
        match = re.search(r"\bDESC '([^']+)'", definition)
        return match.group(1) if match else "unnamed syntax"
    aliases = re.search(r"\bNAME\s+\(\s*([^)]*?)\s*\)", definition)
    if aliases:
        names = re.findall(r"'([^']+)'", aliases.group(1))
        if names:
            return " / ".join(names)
    match = re.search(r"\bNAME\s+'([^']+)'", definition)
    return match.group(1) if match else "unnamed definition"


def parse_definitions(ldif: dict[str, list[str]]) -> dict[str, list[SchemaDefinition]]:
    definitions: dict[str, list[SchemaDefinition]] = {}
    for category in (
        "objectClasses",
        "attributeTypes",
        "matchingRules",
        "ldapSyntaxes",
    ):
        for definition in ldif.get(category, []):
            oid = re.search(r"^\(\s*([0-9.]+)", definition)
            if oid:
                definitions.setdefault(category, []).append(
                    SchemaDefinition(
                        category, definition_name(definition, category), oid.group(1)
                    )
                )
    return definitions


def print_tree(title: str, branches: list[tuple[str, list[str]]]) -> None:
    print(title)
    for branch_index, (label, entries) in enumerate(branches):
        is_last_branch = branch_index == len(branches) - 1
        branch_prefix = "`--" if is_last_branch else "|--"
        child_prefix = "    " if is_last_branch else "|   "
        print(f"{branch_prefix} {label} ({len(entries)})")
        for entry_index, entry in enumerate(entries):
            child_marker = "`--" if entry_index == len(entries) - 1 else "|--"
            print(f"{child_prefix}{child_marker} {entry}")


def full_view(schema_dn: str, definitions: dict[str, list[SchemaDefinition]]) -> None:
    labels = {
        "objectClasses": "Object classes",
        "attributeTypes": "Attribute types",
        "matchingRules": "Matching rules",
        "ldapSyntaxes": "LDAP syntaxes",
    }
    branches = [
        (
            labels[category],
            [f"{item.name} [{item.oid}]" for item in definitions.get(category, [])],
        )
        for category in labels
    ]
    print_tree(f"LDAP schema: {schema_dn}", branches)


def enabled_view(definitions: dict[str, list[SchemaDefinition]]) -> None:
    object_classes = definitions.get("objectClasses", [])
    attribute_types = definitions.get("attributeTypes", [])
    sssd_class_names = {"posixAccount", "posixGroup", "shadowAccount"}
    sssd_attribute_names = {
        "uid",
        "uidNumber",
        "gidNumber",
        "homeDirectory",
        "loginShell",
        "gecos",
        "memberUid",
        "shadowLastChange",
        "shadowMin",
        "shadowMax",
        "shadowWarning",
        "shadowInactive",
        "shadowExpire",
        "shadowFlag",
    }
    sssd_entries = [
        f"Object class: {item.name}"
        for item in object_classes
        if item.name in sssd_class_names
    ]
    sssd_entries += [
        f"Attribute: {item.name}"
        for item in attribute_types
        if item.name in sssd_attribute_names
    ]
    person_entries = [
        f"Object class: {item.name}"
        for item in object_classes
        if item.name == "inetOrgPerson"
    ]
    samba_entries = [
        f"Object class: {item.name}"
        for item in object_classes
        if item.name.startswith("samba")
    ]
    samba_entries += [
        f"Attribute: {item.name}"
        for item in attribute_types
        if item.name.startswith("samba")
    ]

    branches = []
    if sssd_entries:
        branches.append(("Linux accounts / SSSD", sssd_entries))
    if person_entries:
        branches.append(("Person entries", person_entries))
    if samba_entries:
        branches.append(("Samba LDAP", samba_entries))
    print_tree("Active LDAP schema capabilities", branches)


def main(default_view: str) -> None:
    arguments = parse_arguments(default_view)
    port = arguments.port or (636 if arguments.protocol == "ldaps" else 389)
    uri = f"{arguments.protocol}://{arguments.host}:{port}"
    print(f"==> Reading active LDAP schema from {uri}")
    try:
        root_dse = parse_ldif(ldapsearch(arguments, "", "base", ("subschemaSubentry",)))
        schema_dn = root_dse.get("subschemaSubentry", [""])[0]
        if not schema_dn:
            raise RuntimeError("LDAP server did not publish a subschemaSubentry.")
        print(f"==> Schema entry: {schema_dn}")
        schema = ldapsearch(
            arguments,
            schema_dn,
            "base",
            ("objectClasses", "attributeTypes", "ldapSyntaxes", "matchingRules"),
        )
    except (RuntimeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    if arguments.raw:
        print(schema, end="")
        return
    definitions = parse_definitions(parse_ldif(schema))
    if arguments.view == "enabled":
        enabled_view(definitions)
    else:
        full_view(schema_dn, definitions)


if __name__ == "__main__":
    main("full")
