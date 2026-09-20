#!/usr/bin/env python3
import semver
import sys

with open("CHANGELOG.md", encoding="utf-8") as changelog:
    for line in changelog:
        if not line.startswith("## ["):
            continue

        raw_version = line.split("[", 1)[1].split("]", 1)[0]
        if raw_version.lower() == "unreleased":
            continue

        try:
            version = semver.VersionInfo.parse(raw_version.lstrip("v"))
        except ValueError:
            continue

        print(version)
        sys.exit(0)

sys.exit("No valid semver version found in CHANGELOG.md")
