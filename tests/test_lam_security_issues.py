import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "lam-security-issues.py"
spec = importlib.util.spec_from_file_location("lam_security_issues", SCRIPT)
if spec is None:
    raise ImportError(f"Unable to load security monitor from {SCRIPT}")
loader = spec.loader
if loader is None:
    raise ImportError(f"Unable to load security monitor from {SCRIPT}")
monitor = importlib.util.module_from_spec(spec)
loader.exec_module(monitor)


def report(vulnerabilities=None, packages=None):
    return {
        "SchemaVersion": 2,
        "Metadata": {"OS": {"Family": "debian"}},
        "Results": [
            {
                "Class": "os-pkgs",
                "Packages": [
                    {"Name": name}
                    for name in packages or ("nginx", "php8.4-fpm")
                ],
                "Vulnerabilities": vulnerabilities or [],
            }
        ],
    }


def vulnerability(identifier, package, severity="HIGH", fixed=""):
    return {
        "VulnerabilityID": identifier,
        "PkgName": package,
        "InstalledVersion": "1.0",
        "FixedVersion": fixed,
        "Severity": severity,
    }


def issue(identifier, number, state="open", body=None, title="old title"):
    return {
        "number": number,
        "state": state,
        "title": title,
        "body": body or f"<!-- lam-security:v1:{identifier} -->",
    }


class ReportTests(unittest.TestCase):
    def test_groups_packages_and_keeps_unfixed_findings(self):
        data = report(
            [
                vulnerability("CVE-2026-1234", "nginx", fixed="1.1"),
                vulnerability("CVE-2026-1234", "php8.4-fpm", severity="CRITICAL"),
            ]
        )
        findings = monitor.findings_from_report(data)
        self.assertEqual(findings["CVE-2026-1234"]["severity"], "CRITICAL")
        self.assertEqual(
            findings["CVE-2026-1234"]["packages"],
            {("nginx", "1.0", "1.1"), ("php8.4-fpm", "1.0", "No fix available")},
        )

    def test_rejects_incomplete_or_wrong_image_reports(self):
        data = report()
        data["Results"][0]["Packages"] = [{"Name": "nginx"}]
        with self.assertRaises(ValueError):
            monitor.findings_from_report(data)
        data = report()
        data["Metadata"]["OS"]["Family"] = "alpine"
        with self.assertRaises(ValueError):
            monitor.findings_from_report(data)

    def test_validates_openldap_inventory(self):
        data = report(
            [vulnerability("CVE-2026-1234", "slapd", fixed="2.0")],
            packages=("slapd", "ldap-utils"),
        )
        findings = monitor.findings_from_report(data, "openldap")
        self.assertIn("CVE-2026-1234", findings)
        invalid_report = report()
        with self.assertRaisesRegex(ValueError, "slapd"):
            monitor.findings_from_report(invalid_report, "openldap")


class SynchronizationTests(unittest.TestCase):
    def setUp(self):
        self.repo = "owner/repo"
        self.digest = "sha256:" + "a" * 64
        self.findings = monitor.findings_from_report(
            report([vulnerability("CVE-2026-1234", "nginx", fixed="1.1")])
        )

    @patch.object(monitor, "gh_api")
    def test_creates_reopens_and_closes_only_managed_issues(self, api):
        api.return_value = [[
            issue("CVE-2026-1234", 1, "closed"),
            issue("CVE-2026-5678", 2),
            {"number": 3, "state": "open", "body": "unrelated"},
        ]]
        monitor.sync_issues(self.findings, self.digest, self.repo)
        self.assertEqual(api.call_count, 3)
        reopen = api.call_args_list[1]
        self.assertEqual(reopen.args[0], "repos/owner/repo/issues/1")
        self.assertEqual(reopen.args[2]["state"], "open")
        self.assertIn("1.1", reopen.args[2]["body"])
        self.assertEqual(
            api.call_args_list[2].args,
            ("repos/owner/repo/issues/2", "PATCH", {"state": "closed", "state_reason": "completed"}),
        )

    @patch.object(monitor, "gh_api")
    def test_creates_new_issue_and_does_not_rewrite_unchanged_issue(self, api):
        api.return_value = [[]]
        monitor.sync_issues(self.findings, self.digest, self.repo)
        created = api.call_args_list[1].args[2]
        self.assertEqual(created["title"], "[LAM security] CVE-2026-1234 (HIGH)")
        api.reset_mock()
        api.return_value = [[issue(
            "CVE-2026-1234", 1, body=created["body"], title=created["title"]
        )]]
        monitor.sync_issues(self.findings, self.digest, self.repo)
        self.assertEqual(api.call_count, 1)

    @patch.object(monitor, "gh_api")
    def test_groups_unfixed_findings_and_closes_legacy_individual_issues(self, api):
        findings = monitor.findings_from_report(
            report(
                [
                    vulnerability("CVE-2026-1234", "nginx"),
                    vulnerability("CVE-2026-5678", "php8.4-fpm", severity="CRITICAL"),
                ]
            )
        )
        api.return_value = [[
            issue("CVE-2026-1234", 1),
            issue("CVE-2026-5678", 2),
        ]]

        monitor.sync_issues(findings, self.digest, self.repo)

        created = api.call_args_list[1].args[2]
        self.assertEqual(created["title"], "[LAM security] Unfixed vulnerabilities")
        self.assertIn("CVE-2026-1234", created["body"])
        self.assertIn("CVE-2026-5678", created["body"])
        self.assertIn(
            "[CVE-2026-1234](https://security-tracker.debian.org/tracker/CVE-2026-1234)",
            created["body"],
        )
        self.assertEqual(api.call_args_list[2].args[2]["state"], "closed")
        self.assertEqual(api.call_args_list[3].args[2]["state"], "closed")

    @patch.object(monitor, "gh_api")
    def test_keeps_findings_with_available_fixes_individual(self, api):
        findings = monitor.findings_from_report(
            report(
                [
                    vulnerability("CVE-2026-1234", "nginx", fixed="1.1"),
                    vulnerability("CVE-2026-5678", "php8.4-fpm"),
                ]
            )
        )
        api.return_value = [[]]

        monitor.sync_issues(findings, self.digest, self.repo)

        titles = [call.args[2]["title"] for call in api.call_args_list[1:]]
        self.assertIn("[LAM security] CVE-2026-1234 (HIGH)", titles)
        self.assertIn("[LAM security] Unfixed vulnerabilities", titles)
        self.assertEqual(len(titles), 2)

    @patch.object(monitor, "gh_api")
    def test_openldap_uses_separate_issue_markers_and_does_not_close_lam_issues(self, api):
        findings = monitor.findings_from_report(
            report(
                [vulnerability("CVE-2026-1234", "slapd")],
                packages=("slapd", "ldap-utils"),
            ),
            "openldap",
        )
        api.return_value = [[
            issue("CVE-2026-1111", 1),
            issue(
                "CVE-2026-1111",
                2,
                body="<!-- openldap-security:v1:CVE-2026-1111 -->",
            ),
        ]]

        monitor.sync_issues(findings, self.digest, self.repo, "openldap")

        self.assertEqual(api.call_count, 3)
        created = api.call_args_list[1].args[2]
        self.assertEqual(
            created["title"], "[OpenLDAP security] Unfixed vulnerabilities"
        )
        self.assertIn("<!-- openldap-security:v1:UNFIXED -->", created["body"])
        self.assertEqual(
            api.call_args_list[2].args[0], "repos/owner/repo/issues/2"
        )

    @patch.object(monitor, "gh_api")
    def test_duplicate_managed_issues_fail_before_modifying_anything(self, api):
        api.return_value = [[issue("CVE-2026-1234", 1), issue("CVE-2026-1234", 2)]]
        with self.assertRaises(ValueError):
            monitor.sync_issues(self.findings, self.digest, self.repo)
        self.assertEqual(api.call_count, 1)

    @patch.object(monitor.subprocess, "run")
    def test_api_failure_includes_the_github_error(self, run):
        run.side_effect = subprocess.CalledProcessError(
            1, ["gh"], stderr="Resource not accessible by integration"
        )
        with self.assertRaisesRegex(RuntimeError, "Resource not accessible"):
            monitor.gh_api("repos/owner/repo/issues")


if __name__ == "__main__":
    unittest.main()
