"""Safe, subscription-scoped Azure CLI JSON execution."""

import json
import shutil
import subprocess
from uuid import UUID


class AzureCliJsonRunner:
    def __init__(self, subscription_id: str, timeout: int = 60):
        try:
            self.subscription_id = str(UUID(subscription_id))
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("subscription_id must be a valid GUID") from exc
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.timeout = timeout

    def run(self, args: list[str]):
        if not args or any(not isinstance(arg, str) or not arg for arg in args):
            raise ValueError("Azure CLI arguments must be non-empty strings")
        if any(
            arg.lower() in {"--subscription", "-s"}
            or arg.lower().startswith("--subscription=")
            for arg in args
        ):
            raise ValueError("Azure CLI subscription cannot be overridden")

        executable = (
            shutil.which("az") or shutil.which("az.cmd") or shutil.which("az.exe")
        )
        if not executable:
            raise RuntimeError("Azure CLI was not found on PATH")
        result = subprocess.run(
            [
                executable,
                *args,
                "--subscription",
                self.subscription_id,
                "--output",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
            shell=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())
        if not result.stdout.strip():
            return None
        return json.loads(result.stdout.lstrip("\ufeff \t\r\n"))
