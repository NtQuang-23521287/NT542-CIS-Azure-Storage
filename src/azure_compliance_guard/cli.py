import argparse
import json
import os
import sys
from importlib.resources import as_file, files
from pathlib import Path

from azure_compliance_guard.collectors import (
    AzureStorageCollector,
    FixtureStorageCollector,
)
from azure_compliance_guard.doctor import collect_doctor_checks
from azure_compliance_guard.rules import (
    InvalidRuleSetError,
    load_default_rule_catalog,
    load_rule_catalog,
)
from azure_compliance_guard.scan import evaluate_states

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_OPERATIONAL_ERROR = 2
EXIT_CONFIGURATION_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="acg", description="Azure Compliance Guard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="check local runtime readiness")
    doctor.add_argument("--format", choices=("text", "json"), default="text")

    scan = subparsers.add_parser("scan", help="run one compliance scan and exit")
    scan.add_argument("--source", choices=("azure", "fixture"), default="azure")
    scan.add_argument("--fixture", type=Path)
    scan.add_argument("--rules", type=Path)
    scan.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _run_doctor(output_format: str) -> int:
    checks = collect_doctor_checks()
    if output_format == "json":
        print(json.dumps({"checks": checks}, indent=2))
    else:
        for check in checks:
            print(f"[{check['status']}] {check['name']}: {check['detail']}")
    return (
        EXIT_OK
        if all(item["status"] == "PASS" for item in checks)
        else EXIT_OPERATIONAL_ERROR
    )


def _fixture_states(path: Path | None):
    if path is not None:
        return FixtureStorageCollector(path).collect()
    packaged = files("azure_compliance_guard").joinpath("fixtures/storage_drift.json")
    with as_file(packaged) as fixture_path:
        return FixtureStorageCollector(fixture_path).collect()


def _azure_states():
    required = {
        name: os.getenv(name, "").strip()
        for name in (
            "AZURE_TENANT_ID",
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
            "AZURE_SUBSCRIPTION_ID",
            "RESOURCE_GROUP",
            "STORAGE_ACCOUNT_NAME",
        )
    }
    missing = sorted(name for name, value in required.items() if not value)
    if missing:
        raise InvalidRuleSetError(
            "missing Azure scan configuration: " + ", ".join(missing)
        )

    from azure.identity import ClientSecretCredential
    from azure.mgmt.storage import StorageManagementClient

    credential = ClientSecretCredential(
        tenant_id=required["AZURE_TENANT_ID"],
        client_id=required["AZURE_CLIENT_ID"],
        client_secret=required["AZURE_CLIENT_SECRET"],
    )
    client = StorageManagementClient(credential, required["AZURE_SUBSCRIPTION_ID"])
    return AzureStorageCollector(
        client,
        required["RESOURCE_GROUP"],
        required["STORAGE_ACCOUNT_NAME"],
        required["AZURE_SUBSCRIPTION_ID"],
    ).collect()


def _run_scan(args: argparse.Namespace) -> int:
    catalog = (
        load_rule_catalog(args.rules) if args.rules else load_default_rule_catalog()
    )
    states = (
        _fixture_states(args.fixture) if args.source == "fixture" else _azure_states()
    )
    findings = evaluate_states(states, catalog)
    if args.format == "json":
        print(
            json.dumps(
                {
                    "summary": {
                        "resources": len(states),
                        "findings": len(findings),
                    },
                    "findings": [finding.to_dict() for finding in findings],
                },
                indent=2,
            )
        )
    else:
        print(f"Scanned {len(states)} resource(s); {len(findings)} finding(s).")
        for finding in findings:
            print(
                f"[{finding.severity}] {finding.rule_id} "
                f"{finding.resource.name}: {finding.title}"
            )
    return EXIT_FINDINGS if findings else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "doctor":
            return _run_doctor(args.format)
        return _run_scan(args)
    except InvalidRuleSetError as exc:
        print(f"Invalid rule set or configuration: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION_ERROR
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"Invalid fixture or configuration: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION_ERROR
    except (OSError, RuntimeError) as exc:
        print(f"Operational failure: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
