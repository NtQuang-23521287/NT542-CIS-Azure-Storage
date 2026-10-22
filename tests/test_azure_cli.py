from pathlib import Path
from subprocess import CompletedProcess
import sys
from unittest import TestCase
from unittest.mock import patch


ENGINE_DIR = Path(__file__).resolve().parents[1] / "Compliance" / "engine"
sys.path.insert(0, str(ENGINE_DIR))

import azure_cli  # noqa: E402
import collector  # noqa: E402


class AzureCliTests(TestCase):
    def test_run_az_uses_argument_vector_without_a_shell(self):
        with (
            patch.object(azure_cli, "AZURE_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000001"),
            patch.object(azure_cli.shutil, "which", return_value="C:/tools/az.cmd"),
            patch.object(azure_cli.subprocess, "run") as subprocess_run,
        ):
            azure_cli.run_az(["storage", "account", "show", "--name", "demo"])

        subprocess_run.assert_called_once_with(
            [
                "C:/tools/az.cmd", "storage", "account", "show", "--name", "demo",
                "--subscription", "00000000-0000-0000-0000-000000000001",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def test_run_az_refuses_missing_or_invalid_subscription(self):
        with (
            patch.object(azure_cli, "AZURE_SUBSCRIPTION_ID", None),
            patch.object(azure_cli.subprocess, "run") as subprocess_run,
        ):
            with self.assertRaises(ValueError):
                azure_cli.run_az(["storage", "account", "show"])

        subprocess_run.assert_not_called()

    def test_run_az_refuses_subscription_override(self):
        with (
            patch.object(azure_cli, "AZURE_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000001"),
            patch.object(azure_cli.subprocess, "run") as subprocess_run,
        ):
            with self.assertRaises(ValueError):
                azure_cli.run_az([
                    "storage", "account", "show", "--subscription",
                    "11111111-1111-1111-1111-111111111111",
                ])

        subprocess_run.assert_not_called()

    def test_collector_routes_reads_through_scoped_runner(self):
        result = CompletedProcess(args=[], returncode=0, stdout='{"name": "demo"}', stderr="")
        with (
            patch.object(azure_cli, "AZURE_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000001"),
            patch.object(collector, "run_az", return_value=result) as run_az,
        ):
            data = collector._run_az_json(["storage", "account", "show", "--name", "demo"])

        self.assertEqual({"name": "demo"}, data)
        run_az.assert_called_once_with([
            "storage", "account", "show", "--name", "demo", "--output", "json",
        ])


if __name__ == "__main__":
    import unittest

    unittest.main()
