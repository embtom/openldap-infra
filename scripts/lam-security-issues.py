#!/usr/bin/env python3
"""Synchronize issues with a Trivy scan of the published LAM image."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

MARKER = re.compile(r"<!-- (lam|openldap)-security:v1:([A-Za-z0-9._-]+) -->")
SEVERITY_ORDER = {"HIGH": 1, "CRITICAL": 2}
UNFIXED_ISSUE_ID = "UNFIXED"
IMAGES = {
    "ldap-account-manager": {
        "marker": "lam",
        "title": "LAM",
        "required_packages": {"nginx"},
        "php_fpm": True,
    },
    "openldap": {
        "marker": "openldap",
        "title": "OpenLDAP",
        "required_packages": {"slapd"},
        "php_fpm": False,
    },
}


def image_config(image):
    try:
        return IMAGES[image]
    except KeyError as error:
        raise ValueError(f"Unsupported image: {image!r}") from error


def findings_from_report(report, image="ldap-account-manager"):
    if report.get("SchemaVersion") != 2 or report.get("Metadata", {}).get(
        "OS", {}
    ).get("Family") != "debian":
        raise ValueError("Expected a Trivy v2 report for a Debian image")
    config = image_config(image)
    results = report.get("Results")
    if not isinstance(results, list):
        raise ValueError("Trivy report has no results")
    os_results = [result for result in results if result.get("Class") == "os-pkgs"]
    packages = {
        package["Name"]
        for result in os_results
        for package in result.get("Packages", [])
    }
    missing = config["required_packages"] - packages
    has_php_fpm = any(re.fullmatch(r"php[0-9.]+-fpm", name) for name in packages)
    if missing or (config["php_fpm"] and not has_php_fpm):
        expected = ", ".join(sorted(config["required_packages"]))
        if config["php_fpm"]:
            expected += " and PHP-FPM"
        raise ValueError(f"Scan did not inventory the expected {expected} packages")

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


def issue_body(identifier, finding, digest, repo, image="ldap-account-manager"):
    config = image_config(image)
    rows = "\n".join(
        f"| {name} | {installed} | {fixed} |"
        for name, installed, fixed in sorted(finding["packages"])
    )
    return (
        f"<!-- {config['marker']}-security:v1:{identifier} -->\n"
        f"Trivy detected **{finding['severity']}** {identifier} in the published "
        f"`{image}:latest` image (`{digest}`).\n\n"
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


def unfixed_issue_body(findings, digest, repo, image="ldap-account-manager"):
    config = image_config(image)
    rows = "\n".join(
        f"| [{identifier}](https://security-tracker.debian.org/tracker/{identifier}) "
        f"| {finding['severity']} | {name} | {installed} |"
        for identifier, finding in sorted(findings.items())
        for name, installed, _ in sorted(finding["packages"])
    )
    return (
        f"<!-- {config['marker']}-security:v1:{UNFIXED_ISSUE_ID} -->\n"
        "Trivy detected the following HIGH or CRITICAL vulnerabilities in the "
        f"published `{image}:latest` image (`{digest}`) with no Debian fix "
        "currently available.\n\n"
        "| Vulnerability | Severity | Debian package | Installed version |\n"
        "| --- | --- | --- | --- |\n"
        f"{rows}\n\n"
        "See the [Debian security tracker](https://security-tracker.debian.org/) "
        "for package-specific status. Debian may backport fixes without changing "
        "the upstream version.\n\n"
        f"Check the [security workflow](https://github.com/{repo}/actions/workflows/lam-security.yml) "
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
        raise RuntimeError(f"GitHub API request failed: {error.stderr.strip()}") from error
    return json.loads(result.stdout)


def sync_issues(findings, digest, repo, image="ldap-account-manager"):
    config = image_config(image)
    endpoint = f"repos/{repo}/issues"
    pages = gh_api(f"{endpoint}?state=all&per_page=100", paginate=True)
    managed = {}
    for issue in (item for page in pages for item in page):
        if "pull_request" in issue:
            continue
        match = MARKER.search(issue.get("body") or "")
        if not match:
            continue
        if match.group(1) != config["marker"]:
            continue
        identifier = match.group(2)
        if identifier in managed:
            raise ValueError(f"Multiple managed issues for {identifier}")
        managed[identifier] = issue

    actionable = {
        identifier: finding
        for identifier, finding in findings.items()
        if any(fixed != "No fix available" for _, _, fixed in finding["packages"])
    }
    unfixed = {
        identifier: finding
        for identifier, finding in findings.items()
        if identifier not in actionable
    }
    desired = {}
    for identifier, finding in sorted(actionable.items()):
        title = f"[{config['title']} security] {identifier} ({finding['severity']})"
        body = issue_body(identifier, finding, digest, repo, image)
        desired[identifier] = (title, body)

    if unfixed:
        desired[UNFIXED_ISSUE_ID] = (
            f"[{config['title']} security] Unfixed vulnerabilities",
            unfixed_issue_body(unfixed, digest, repo, image),
        )

    for identifier, (title, body) in desired.items():
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
        if identifier not in desired and issue["state"] == "open":
            gh_api(
                f"{endpoint}/{issue['number']}",
                "PATCH",
                {"state": "closed", "state_reason": "completed"},
            )


def main():
    if len(sys.argv) not in (3, 4):
        raise SystemExit(
            "Usage: lam-security-issues.py REPORT.json IMAGE_DIGEST [IMAGE_NAME]"
        )
    image = sys.argv[3] if len(sys.argv) == 4 else "ldap-account-manager"
    digest = sys.argv[2]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("Expected a sha256 image digest")
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    sync_issues(
        findings_from_report(report, image),
        digest,
        os.environ["GH_REPO"],
        image,
    )


if __name__ == "__main__":
    main()
