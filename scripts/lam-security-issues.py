#!/usr/bin/env python3
"""Synchronize issues with a Trivy scan of the published LAM image."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

MARKER = re.compile(r"<!-- lam-security:v1:([A-Za-z0-9._-]+) -->")
SEVERITY_ORDER = {"HIGH": 1, "CRITICAL": 2}


def findings_from_report(report):
    if report.get("SchemaVersion") != 2 or report.get("Metadata", {}).get(
        "OS", {}
    ).get("Family") != "debian":
        raise ValueError("Expected a Trivy v2 report for a Debian image")
    results = report.get("Results")
    if not isinstance(results, list):
        raise ValueError("Trivy report has no results")
    os_results = [result for result in results if result.get("Class") == "os-pkgs"]
    packages = {
        package["Name"]
        for result in os_results
        for package in result.get("Packages", [])
    }
    if "nginx" not in packages or not any(
        re.fullmatch(r"php[0-9.]+-fpm", name) for name in packages
    ):
        raise ValueError("Scan did not inventory the expected nginx and PHP packages")

    findings = {}
    for result in os_results:
        for vulnerability in result.get("Vulnerabilities", []):
            identifier = vulnerability["VulnerabilityID"]
            if not re.fullmatch(r"[A-Za-z0-9._-]+", identifier):
                raise ValueError(f"Invalid vulnerability ID: {identifier!r}")
            severity = vulnerability["Severity"]
            if severity not in SEVERITY_ORDER:
                raise ValueError(f"Unexpected vulnerability severity: {severity!r}")
            entry = findings.setdefault(identifier, {"severity": severity, "packages": set()})
            if SEVERITY_ORDER[severity] > SEVERITY_ORDER[entry["severity"]]:
                entry["severity"] = severity
            entry["packages"].add(
                (
                    vulnerability["PkgName"],
                    vulnerability["InstalledVersion"],
                    vulnerability.get("FixedVersion") or "No fix available",
                )
            )
    return findings


def issue_body(identifier, finding, digest, repo):
    rows = "\n".join(
        f"| {name} | {installed} | {fixed} |"
        for name, installed, fixed in sorted(finding["packages"])
    )
    return (
        f"<!-- lam-security:v1:{identifier} -->\n"
        f"Trivy detected **{finding['severity']}** {identifier} in the published "
        f"`ldap-account-manager:latest` image (`{digest}`).\n\n"
        "| Debian package | Installed version | Fixed version |\n"
        "| --- | --- | --- |\n"
        f"{rows}\n\n"
        f"See the [Debian security tracker](https://security-tracker.debian.org/tracker/{identifier}) "
        "for package-specific status. Debian may backport fixes without changing "
        "the upstream version.\n\n"
        f"Check the [security workflow](https://github.com/{repo}/actions/workflows/lam-security.yml) "
        "for the fresh-build scan. When a fix is available, run the CI workflow "
        "on `main` to rebuild and publish the images, then update and restart "
        "the deployment. Release-tagged and direct-build deployments require "
        "their own update. This issue tracks the published `latest` image, not "
        "the image running on a host.\n\n"
        "The monitor reopens this issue if the finding returns and closes it "
        "when a successful scan no longer reports it."
    )


def gh_api(endpoint, method="GET", data=None, paginate=False):
    command = ["gh", "api", "--method", method]
    if paginate:
        command.extend(["--paginate", "--slurp"])
    if data is not None:
        command.extend(["--input", "-"])
    command.append(endpoint)
    try:
        result = subprocess.run(
            command,
            input=json.dumps(data) if data is not None else None,
            text=True,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"GitHub API request failed: {error.stderr.strip()}") from error
    return json.loads(result.stdout)


def sync_issues(findings, digest, repo):
    endpoint = f"repos/{repo}/issues"
    pages = gh_api(f"{endpoint}?state=all&per_page=100", paginate=True)
    managed = {}
    for issue in (item for page in pages for item in page):
        if "pull_request" in issue:
            continue
        match = MARKER.search(issue.get("body") or "")
        if not match:
            continue
        identifier = match.group(1)
        if identifier in managed:
            raise ValueError(f"Multiple managed issues for {identifier}")
        managed[identifier] = issue

    for identifier, finding in sorted(findings.items()):
        title = f"[LAM security] {identifier} ({finding['severity']})"
        body = issue_body(identifier, finding, digest, repo)
        issue = managed.get(identifier)
        if issue is None:
            gh_api(endpoint, "POST", {"title": title, "body": body})
        elif issue["state"] != "open" or issue["title"] != title or issue["body"] != body:
            gh_api(
                f"{endpoint}/{issue['number']}",
                "PATCH",
                {"title": title, "body": body, "state": "open"},
            )

    for identifier, issue in managed.items():
        if identifier not in findings and issue["state"] == "open":
            gh_api(
                f"{endpoint}/{issue['number']}",
                "PATCH",
                {"state": "closed", "state_reason": "completed"},
            )


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: lam-security-issues.py REPORT.json IMAGE_DIGEST")
    digest = sys.argv[2]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("Expected a sha256 image digest")
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    sync_issues(findings_from_report(report), digest, os.environ["GH_REPO"])


if __name__ == "__main__":
    main()
