#!/usr/bin/env python3
"""Synchronize issues with Trivy scans of published container images."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

IMAGES = {
    "ldap-account-manager": {"marker": "lam-security", "label": "LAM"},
    "openldap": {"marker": "openldap-security", "label": "OpenLDAP"},
}
SEVERITY_ORDER = {"HIGH": 1, "CRITICAL": 2}
UNFIXED_ISSUE_ID = "UNFIXED"


def findings_from_report(report, image):
    if (
        report.get("SchemaVersion") != 2
        or report.get("Metadata", {}).get("OS", {}).get("Family") != "debian"
    ):
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
    if image == "ldap-account-manager":
        valid = "nginx" in packages and any(
            re.fullmatch(r"php[0-9.]+-fpm", name) for name in packages
        )
        expected = "nginx and PHP FPM"
    elif image == "openldap":
        valid = {"slapd", "ldap-utils"} <= packages
        expected = "slapd and ldap-utils"
    else:
        raise ValueError(f"Unknown image: {image!r}")
    if not valid:
        raise ValueError(f"Scan did not inventory the expected {image} packages: {expected}")

    findings = {}
    for result in os_results:
        for vulnerability in result.get("Vulnerabilities", []):
            identifier = vulnerability["VulnerabilityID"]
            if identifier == UNFIXED_ISSUE_ID or not re.fullmatch(
                r"[A-Za-z0-9._-]+", identifier
            ):
                raise ValueError(f"Invalid vulnerability ID: {identifier!r}")
            severity = vulnerability["Severity"]
            if severity not in SEVERITY_ORDER:
                raise ValueError(f"Unexpected vulnerability severity: {severity!r}")
            entry = findings.setdefault(
                identifier, {"severity": severity, "packages": set()}
            )
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


def issue_body(identifier, finding, digest, repo, image):
    rows = "\n".join(
        f"| {name} | {installed} | {fixed} |"
        for name, installed, fixed in sorted(finding["packages"])
    )
    return (
        f"<!-- {IMAGES[image]['marker']}:v1:{identifier} -->\n"
        f"Trivy detected **{finding['severity']}** {identifier} in the published "
        f"`{image}:latest` image (`{digest}`).\n\n"
        "| Debian package | Installed version | Fixed version |\n"
        "| --- | --- | --- |\n"
        f"{rows}\n\n"
        f"See the [Debian security tracker](https://security-tracker.debian.org/tracker/{identifier}) "
        "for package-specific status. Debian may backport fixes without changing "
        "the upstream version.\n\n"
        f"Check the [security workflow](https://github.com/{repo}/actions/workflows/container-security.yml) "
        "for the fresh-build scan. When a fix is available, run the CI workflow "
        "on `main` to rebuild and publish the images, then update and restart "
        "the deployment. Release-tagged and direct-build deployments require "
        "their own update. This issue tracks the published `latest` image, not "
        "the image running on a host.\n\n"
        "The monitor reopens this issue if the finding returns and closes it "
        "when a successful scan no longer reports it."
    )


def unfixed_issue_body(findings, digest, repo, advisories, image="ldap-account-manager"):
    rows = "\n".join(
        f"| [{identifier}](https://security-tracker.debian.org/tracker/{identifier}) "
        f"| {advisories.get(identifier) or 'Not found'} "
        f"| {finding['severity']} | {name} | {installed} |"
        for identifier, finding in sorted(findings.items())
        for name, installed, _ in sorted(finding["packages"])
    )
    return (
        f"<!-- {IMAGES[image]['marker']}:v1:{UNFIXED_ISSUE_ID} -->\n"
        "Trivy detected the following HIGH or CRITICAL vulnerabilities in the "
        f"published `{image}:latest` image (`{digest}`) with no Debian fix "
        "currently available.\n\n"
        "| Vulnerability | GitHub advisory | Severity | Debian package | Installed version |\n"
        "| --- | --- | --- | --- | --- |\n"
        f"{rows}\n\n"
        "See the [Debian security tracker](https://security-tracker.debian.org/) "
        "for package-specific status. Debian may backport fixes without changing "
        "the upstream version.\n\n"
        f"Check the [security workflow](https://github.com/{repo}/actions/workflows/container-security.yml) "
        "for fresh-build scans. This issue tracks the published `latest` image, "
        "not the image running on a host. The monitor updates this list, closes "
        "it when no unfixed findings remain, and reopens it if findings return."
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
        raise RuntimeError(
            f"GitHub API request failed: {error.stderr.strip()}"
        ) from error
    return json.loads(result.stdout)


def github_advisory_links(identifiers):
    links = {}
    for identifier in sorted(identifiers):
        if re.fullmatch(
            r"GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}", identifier
        ):
            ids = {identifier}
        elif re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", identifier):
            pages = gh_api(f"advisories?cve_id={identifier}&per_page=100", paginate=True)
            ids = {advisory["ghsa_id"] for page in pages for advisory in page}
            if any(
                not re.fullmatch(
                    r"GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}", ghsa
                )
                for ghsa in ids
            ):
                raise ValueError(f"Invalid GitHub advisory ID for {identifier}")
        else:
            ids = set()
        links[identifier] = ", ".join(
            f"[{ghsa}](https://github.com/advisories/{ghsa})" for ghsa in sorted(ids)
        )
    return links


def sync_issues(findings, digest, repo, image):
    endpoint = f"repos/{repo}/issues"
    marker = re.compile(
        rf"<!-- {re.escape(IMAGES[image]['marker'])}:v1:([A-Za-z0-9._-]+) -->"
    )
    pages = gh_api(f"{endpoint}?state=all&per_page=100", paginate=True)
    managed = {}
    for issue in (item for page in pages for item in page):
        if "pull_request" in issue:
            continue
        match = marker.search(issue.get("body") or "")
        if not match:
            continue
        identifier = match.group(1)
        if identifier in managed:
            raise ValueError(f"Multiple managed issues for {identifier}")
        managed[identifier] = issue

    desired = {}
    unfixed = {}
    for identifier, finding in sorted(findings.items()):
        fixed_packages = {package for package in finding["packages"] if package[2] != "No fix available"}
        unfixed_packages = finding["packages"] - fixed_packages
        if unfixed_packages:
            unfixed[identifier] = {**finding, "packages": unfixed_packages}
        if not fixed_packages:
            continue
        title = (
            f"[{IMAGES[image]['label']} security] {identifier} ({finding['severity']})"
        )
        body = issue_body(identifier, {**finding, "packages": fixed_packages}, digest, repo, image)
        desired[identifier] = (title, body)

    if unfixed:
        advisories = github_advisory_links(unfixed)
        desired[UNFIXED_ISSUE_ID] = (
            f"[{IMAGES[image]['label']} security] Unfixed vulnerabilities",
            unfixed_issue_body(unfixed, digest, repo, advisories, image),
        )

    for identifier, (title, body) in desired.items():
        issue = managed.get(identifier)
        if issue is None:
            gh_api(endpoint, "POST", {"title": title, "body": body})
        elif (
            issue["state"] != "open" or issue["title"] != title or issue["body"] != body
        ):
            gh_api(
                f"{endpoint}/{issue['number']}",
                "PATCH",
                {"title": title, "body": body, "state": "open"},
            )

    for identifier, issue in managed.items():
        if identifier not in desired and issue["state"] == "open":
            gh_api(
                f"{endpoint}/{issue['number']}",
                "PATCH",
                {"state": "closed", "state_reason": "completed"},
            )


def main():
    if len(sys.argv) != 4 or sys.argv[3] not in IMAGES:
        raise SystemExit(
            "Usage: container-security-issues.py REPORT.json IMAGE_DIGEST "
            "{openldap,ldap-account-manager}"
        )
    digest = sys.argv[2]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("Expected a sha256 image digest")
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    image = sys.argv[3]
    sync_issues(
        findings_from_report(report, image), digest, os.environ["GH_REPO"], image
    )


if __name__ == "__main__":
    main()
