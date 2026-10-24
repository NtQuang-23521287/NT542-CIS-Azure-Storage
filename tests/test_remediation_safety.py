import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

ENGINE_DIR = Path(__file__).resolve().parents[1] / "Compliance" / "engine"
sys.path.insert(0, str(ENGINE_DIR))

import azure_cli  # noqa: E402
import incident_response  # noqa: E402
import remediation  # noqa: E402


class RemediationSafetyTests(TestCase):
    def test_critical_remediation_is_plan_only_by_default(self):
        issue = {"name": "Public Network Access mismatch", "severity": "CRITICAL"}

        with (
            patch.object(
                azure_cli,
                "AZURE_SUBSCRIPTION_ID",
                "00000000-0000-0000-0000-000000000001",
            ),
            patch.object(remediation, "find_active_exception", return_value=None),
            patch.object(remediation, "_run_command") as run_command,
            patch.object(remediation, "log_compliance_event"),
        ):
            remediation.remediate_config("rg-demo", "storage-demo", [issue])

        run_command.assert_not_called()

    def test_incident_containment_is_plan_only_by_default(self):
        issue = {"name": "Suspicious access", "service": "storage"}

        with (
            patch.object(
                azure_cli,
                "AZURE_SUBSCRIPTION_ID",
                "00000000-0000-0000-0000-000000000001",
            ),
            patch.object(azure_cli, "run_az") as run_az,
        ):
            status, command = incident_response._run_containment(
                "rg-demo",
                "storage-demo",
                issue,
            )

        self.assertEqual("PLANNED", status)
        self.assertIn("--public-network-access Disabled", command)
        run_az.assert_not_called()

    def test_paid_defender_remediation_is_never_automatic(self):
        issue = {"name": "Microsoft Defender for SQL disabled", "severity": "CRITICAL"}

        with (
            patch.object(remediation, "find_active_exception", return_value=None),
            patch.object(remediation, "_run_command") as run_command,
            patch.object(remediation, "log_compliance_event"),
        ):
            remediation.remediate_config(
                "rg-demo",
                "sql-demo",
                [issue],
                allow_mutation=True,
            )

        run_command.assert_not_called()

    def test_legacy_opt_in_cannot_bypass_exact_plan_approval(self):
        issue = {"name": "Public Network Access mismatch", "severity": "CRITICAL"}
        with (
            patch.object(
                azure_cli,
                "AZURE_SUBSCRIPTION_ID",
                "00000000-0000-0000-0000-000000000001",
            ),
            patch.object(remediation, "find_active_exception", return_value=None),
            patch.object(remediation, "_run_command") as run_command,
            patch.object(remediation, "log_compliance_event"),
        ):
            remediation.remediate_config(
                "rg-demo", "storage-demo", [issue], allow_mutation=True
            )
        run_command.assert_not_called()

    def test_legacy_incident_opt_in_cannot_bypass_approval(self):
        issue = {"name": "Suspicious access", "service": "storage"}
        with (
            patch.object(
                azure_cli,
                "AZURE_SUBSCRIPTION_ID",
                "00000000-0000-0000-0000-000000000001",
            ),
            patch.object(azure_cli, "run_az") as run_az,
        ):
            status, _command = incident_response._run_containment(
                "rg-demo", "storage-demo", issue, allow_mutation=True
            )
        self.assertEqual("PLANNED", status)
        run_az.assert_not_called()


if __name__ == "__main__":
    import unittest

    unittest.main()
