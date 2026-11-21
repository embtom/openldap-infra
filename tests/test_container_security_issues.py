import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "container-security-issues.py"
)
spec = importlib.util.spec_from_file_location("container_security_issues", SCRIPT)
if spec is None or spec.loader is None:
    raise ImportError(f"Unable to load {SCRIPT}")
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)


def report(vulnerabilities=None, packages=None):
    return {
        "SchemaVersion": 2,
        "Metadata": {"OS": {"Family": "debian"}},
        "Results": [
            {
                "Class": "os-pkgs",
                "Packages": [
                    {"Name": name}
                    for name in (
                        packages if packages is not None else ["nginx", "php8.4-fpm"]
                    )
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
        findings = monitor.findings_from_report(data, "ldap-account-manager")
        self.assertEqual(findings["CVE-2026-1234"]["severity"], "CRITICAL")
        self.assertEqual(
            findings["CVE-2026-1234"]["packages"],
            {("nginx", "1.0", "1.1"), ("php8.4-fpm", "1.0", "No fix available")},
        )

    def test_rejects_incomplete_or_wrong_image_reports(self):
        data = report()
        data["Results"][0]["Packages"] = [{"Name": "nginx"}]
        with self.assertRaises(ValueError):
            monitor.findings_from_report(data, "ldap-account-manager")
        data = report()
        data["Metadata"]["OS"]["Family"] = "alpine"
        with self.assertRaises(ValueError):
            monitor.findings_from_report(data, "ldap-account-manager")

    def test_openldap_requires_its_own_packages(self):
        data = report(
            [vulnerability("CVE-2026-1234", "slapd")], ["slapd", "ldap-utils"]
        )
        self.assertIn("CVE-2026-1234", monitor.findings_from_report(data, "openldap"))
        with self.assertRaises(ValueError):
            monitor.findings_from_report(data, "ldap-account-manager")
        with self.assertRaises(ValueError):
            monitor.findings_from_report(report(), "openldap")
        with self.assertRaises(ValueError):
            monitor.findings_from_report(report(packages=["slapd"]), "openldap")

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
        advisory_patch = patch.object(monitor, "github_advisory_links", return_value={})
        self.advisory_lookup = advisory_patch.start()
        self.addCleanup(advisory_patch.stop)
        self.repo = "owner/repo"
        self.digest = "sha256:" + "a" * 64
        self.findings = monitor.findings_from_report(
            report([vulnerability("CVE-2026-1234", "nginx", fixed="1.1")]),
            "ldap-account-manager",
        )

    @patch.object(monitor, "gh_api")
    def test_creates_reopens_and_closes_only_managed_issues(self, api):
        api.return_value = [
            [
                issue("CVE-2026-1234", 1, "closed"),
                issue("CVE-2026-5678", 2),
                {"number": 3, "state": "open", "body": "unrelated"},
            ]
        ]
        monitor.sync_issues(
            self.findings, self.digest, self.repo, "ldap-account-manager"
        )
        self.assertEqual(api.call_count, 3)
        reopen = api.call_args_list[1]
        self.assertEqual(reopen.args[0], "repos/owner/repo/issues/1")
        self.assertEqual(reopen.args[2]["state"], "open")
        self.assertIn("1.1", reopen.args[2]["body"])
        self.assertEqual(
            api.call_args_list[2].args,
            (
                "repos/owner/repo/issues/2",
                "PATCH",
                {"state": "closed", "state_reason": "completed"},
            ),
        )

    @patch.object(monitor, "gh_api")
    def test_creates_new_issue_and_does_not_rewrite_unchanged_issue(self, api):
        api.return_value = [[]]
        monitor.sync_issues(
            self.findings, self.digest, self.repo, "ldap-account-manager"
        )
        created = api.call_args_list[1].args[2]
        self.assertEqual(created["title"], "[LAM security] CVE-2026-1234 (HIGH)")
        api.reset_mock()
        api.return_value = [
            [issue("CVE-2026-1234", 1, body=created["body"], title=created["title"])]
        ]
        monitor.sync_issues(
            self.findings, self.digest, self.repo, "ldap-account-manager"
        )
        self.assertEqual(api.call_count, 1)

    @patch.object(monitor, "gh_api")
    def test_groups_unfixed_findings_and_closes_legacy_individual_issues(self, api):
        self.advisory_lookup.return_value = {
            "CVE-2026-1234": "[GHSA-499q-6rmh-w6p7](https://github.com/advisories/GHSA-499q-6rmh-w6p7)"
        }
        findings = monitor.findings_from_report(
            report(
                [
                    vulnerability("CVE-2026-1234", "nginx"),
                    vulnerability("CVE-2026-5678", "php8.4-fpm", severity="CRITICAL"),
                ]
            ),
            "ldap-account-manager",
        )
        api.return_value = [
            [
                issue("CVE-2026-1234", 1),
                issue("CVE-2026-5678", 2),
            ]
        ]

        monitor.sync_issues(findings, self.digest, self.repo, "ldap-account-manager")

        created = api.call_args_list[1].args[2]
        self.assertEqual(created["title"], "[LAM security] Unfixed vulnerabilities")
        self.assertIn("CVE-2026-1234", created["body"])
        self.assertIn("CVE-2026-5678", created["body"])
        self.assertIn("| GitHub advisory |", created["body"])
        self.assertIn(
            "[GHSA-499q-6rmh-w6p7](https://github.com/advisories/GHSA-499q-6rmh-w6p7)",
            created["body"],
        )
        self.assertIn("| Not found |", created["body"])
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
            ),
            "ldap-account-manager",
        )
        api.return_value = [[]]

        monitor.sync_issues(findings, self.digest, self.repo, "ldap-account-manager")

        titles = [call.args[2]["title"] for call in api.call_args_list[1:]]
        self.assertIn("[LAM security] CVE-2026-1234 (HIGH)", titles)
        self.assertIn("[LAM security] Unfixed vulnerabilities", titles)
        self.assertEqual(len(titles), 2)

    @patch.object(monitor, "gh_api")
    def test_splits_fixed_and_unfixed_packages_of_the_same_vulnerability(self, api):
        findings = monitor.findings_from_report(
            report(
                [
                    vulnerability("CVE-2026-1234", "nginx", fixed="1.1"),
                    vulnerability("CVE-2026-1234", "php8.4-fpm"),
                ]
            ),
            "ldap-account-manager",
        )
        api.return_value = [[]]
        monitor.sync_issues(findings, self.digest, self.repo, "ldap-account-manager")
        individual = api.call_args_list[1].args[2]["body"]
        grouped = api.call_args_list[2].args[2]["body"]
        self.assertIn("nginx", individual)
        self.assertNotIn("php8.4-fpm", individual)
        self.assertIn("php8.4-fpm", grouped)
        self.assertNotIn("nginx", grouped)

    @patch.object(monitor, "gh_api")
    def test_closes_unfixed_group_when_no_unfixed_packages_remain(self, api):
        api.return_value = [[issue("UNFIXED", 2)]]
        monitor.sync_issues(self.findings, self.digest, self.repo, "ldap-account-manager")
        self.assertEqual(api.call_args_list[2].args[0], "repos/owner/repo/issues/2")
        self.assertEqual(api.call_args_list[2].args[2]["state"], "closed")

    @patch.object(monitor, "gh_api")
    def test_openldap_uses_separate_issue_markers_and_does_not_close_lam_issues(
        self, api
    ):
        findings = monitor.findings_from_report(
            report(
                [vulnerability("CVE-2026-1234", "slapd")],
                packages=("slapd", "ldap-utils"),
            ),
            "openldap",
        )
        api.return_value = [
            [
                issue("CVE-2026-1111", 1),
                issue(
                    "CVE-2026-1111",
                    2,
                    body="<!-- openldap-security:v1:CVE-2026-1111 -->",
                ),
            ]
        ]

        monitor.sync_issues(findings, self.digest, self.repo, "openldap")

        self.assertEqual(api.call_count, 3)
        created = api.call_args_list[1].args[2]
        self.assertEqual(
            created["title"], "[OpenLDAP security] Unfixed vulnerabilities"
        )
        self.assertIn("<!-- openldap-security:v1:UNFIXED -->", created["body"])
        self.assertEqual(api.call_args_list[2].args[0], "repos/owner/repo/issues/2")

    @patch.object(monitor, "gh_api")
    def test_duplicate_managed_issues_fail_before_modifying_anything(self, api):
        api.return_value = [[issue("CVE-2026-1234", 1), issue("CVE-2026-1234", 2)]]
        with self.assertRaises(ValueError):
            monitor.sync_issues(
                self.findings, self.digest, self.repo, "ldap-account-manager"
            )
        self.assertEqual(api.call_count, 1)

    @patch.object(monitor, "gh_api")
    def test_images_manage_separate_issues_for_the_same_vulnerability(self, api):
        api.return_value = [
            [
                issue("CVE-2026-1234", 1),
                issue(
                    "CVE-2026-5678",
                    2,
                    body="<!-- openldap-security:v1:CVE-2026-5678 -->",
                ),
            ]
        ]
        monitor.sync_issues(self.findings, self.digest, self.repo, "openldap")
        self.assertEqual(
            api.call_args_list[1].args[2]["title"],
            "[OpenLDAP security] CVE-2026-1234 (HIGH)",
        )
        self.assertIn(
            "<!-- openldap-security:v1:CVE-2026-1234 -->",
            api.call_args_list[1].args[2]["body"],
        )
        self.assertIn("`openldap:latest`", api.call_args_list[1].args[2]["body"])
        self.assertEqual(api.call_args_list[2].args[0], "repos/owner/repo/issues/2")
        self.assertEqual(api.call_count, 3)

        api.reset_mock()
        api.return_value = [
            [
                issue(
                    "CVE-2026-1234",
                    1,
                    body="<!-- openldap-security:v1:CVE-2026-1234 -->",
                ),
            ]
        ]
        monitor.sync_issues({}, self.digest, self.repo, "ldap-account-manager")
        self.assertEqual(api.call_count, 1)

    @patch.object(monitor, "gh_api")
    def test_openldap_reopens_its_issue_without_changing_lam_issue(self, api):
        api.return_value = [
            [
                issue("CVE-2026-1234", 1),
                issue(
                    "CVE-2026-1234",
                    2,
                    "closed",
                    body="<!-- openldap-security:v1:CVE-2026-1234 -->",
                ),
            ]
        ]
        monitor.sync_issues(self.findings, self.digest, self.repo, "openldap")
        self.assertEqual(api.call_count, 2)
        self.assertEqual(api.call_args_list[1].args[0], "repos/owner/repo/issues/2")
        self.assertEqual(api.call_args_list[1].args[2]["state"], "open")

    @patch.object(monitor.subprocess, "run")
    def test_api_failure_includes_the_github_error(self, run):
        run.side_effect = subprocess.CalledProcessError(
            1, ["gh"], stderr="Resource not accessible by integration"
        )
        with self.assertRaisesRegex(RuntimeError, "Resource not accessible"):
            monitor.gh_api("repos/owner/repo/issues")


class AdvisoryTests(unittest.TestCase):
    @patch.object(monitor, "gh_api")
    def test_resolves_cve_and_uses_direct_ghsa_links(self, api):
        api.return_value = [[{"ghsa_id": "GHSA-499q-6rmh-w6p7"}]]
        links = monitor.github_advisory_links(
            ["CVE-2026-86142", "GHSA-aaaa-bbbb-cccc"]
        )
        self.assertEqual(
            links["CVE-2026-86142"],
            "[GHSA-499q-6rmh-w6p7](https://github.com/advisories/GHSA-499q-6rmh-w6p7)",
        )
        self.assertIn(
            "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
            links["GHSA-aaaa-bbbb-cccc"],
        )
        api.assert_called_once_with(
            "advisories?cve_id=CVE-2026-86142&per_page=100", paginate=True
        )

    @patch.object(monitor, "gh_api")
    def test_missing_advisory_and_api_failure(self, api):
        api.return_value = [[]]
        self.assertEqual(
            monitor.github_advisory_links(["CVE-2026-1234"])["CVE-2026-1234"], ""
        )
        api.side_effect = RuntimeError("API unavailable")
        with self.assertRaisesRegex(RuntimeError, "API unavailable"):
            monitor.github_advisory_links(["CVE-2026-1234"])


if __name__ == "__main__":
    unittest.main()
