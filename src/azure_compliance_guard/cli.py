import argparse
import json
import math
import os
import sys
import time
from importlib.resources import as_file, files
from pathlib import Path

from azure_compliance_guard.azure_cli import AzureCliJsonRunner
from azure_compliance_guard.collectors import (
    AzureKeyVaultCollector,
    AzureSqlCollector,
    AzureStorageCollector,
    FixtureKeyVaultCollector,
    FixtureSqlCollector,
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


def _positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return parsed


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source", choices=("azure", "fixture"), default="azure")
    parser.add_argument(
        "--service",
        choices=("storage", "key-vault", "sql", "all"),
        default="storage",
    )
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--rules", type=Path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="acg", description="Azure Compliance Guard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="check local runtime readiness")
    doctor.add_argument("--format", choices=("text", "json"), default="text")

    scan = subparsers.add_parser("scan", help="run one compliance scan and exit")
    _add_scan_arguments(scan)
    scan.add_argument("--format", choices=("text", "json"), default="text")

    watch = subparsers.add_parser("watch", help="run compliance scans repeatedly")
    _add_scan_arguments(watch)
    watch.add_argument("--format", choices=("text", "jsonl"), default="text")
    watch.add_argument("--interval", type=_positive_float, default=60.0)
    watch.add_argument("--iterations", type=_positive_int)
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


FIXTURE_COLLECTORS = {
    "storage": FixtureStorageCollector,
    "key-vault": FixtureKeyVaultCollector,
    "sql": FixtureSqlCollector,
}
PACKAGED_DRIFT_FIXTURES = {
    "storage": "storage_drift.json",
    "key-vault": "key_vault_drift.json",
    "sql": "sql_drift.json",
}


def _selected_services(service: str) -> tuple[str, ...]:
    if service == "all":
        return tuple(FIXTURE_COLLECTORS)
    return (service,)


def _fixture_states(path: Path | None, service: str):
    states = []
    for selected in _selected_services(service):
        collector = FIXTURE_COLLECTORS[selected]
        if path is not None:
            states.extend(collector(path).collect())
            continue
        packaged = files("azure_compliance_guard").joinpath(
            f"fixtures/{PACKAGED_DRIFT_FIXTURES[selected]}"
        )
        with as_file(packaged) as fixture_path:
            states.extend(collector(fixture_path).collect())
    return states


def _required_environment(names: tuple[str, ...]) -> dict[str, str]:
    required = {name: os.getenv(name, "").strip() for name in names}
    missing = sorted(name for name, value in required.items() if not value)
    if missing:
        raise InvalidRuleSetError(
            "missing Azure scan configuration: " + ", ".join(missing)
        )
    return required


def _azure_states(service: str):
    if service == "all":
        states = []
        for selected in ("storage", "key-vault", "sql"):
            states.extend(_azure_states(selected))
        return states

    common = _required_environment(("AZURE_SUBSCRIPTION_ID", "RESOURCE_GROUP"))
    if service == "key-vault":
        required = {
            **common,
            **_required_environment(("KEY_VAULT_NAME",)),
        }
        runner = AzureCliJsonRunner(required["AZURE_SUBSCRIPTION_ID"])
        return AzureKeyVaultCollector(
            runner,
            required["RESOURCE_GROUP"],
            required["KEY_VAULT_NAME"],
            runner.subscription_id,
        ).collect()
    if service == "sql":
        required = {
            **common,
            **_required_environment(("SQL_SERVER_NAME",)),
        }
        runner = AzureCliJsonRunner(required["AZURE_SUBSCRIPTION_ID"])
        return AzureSqlCollector(
            runner,
            required["RESOURCE_GROUP"],
            required["SQL_SERVER_NAME"],
            runner.subscription_id,
        ).collect()

    required = {
        **common,
        **_required_environment(
            (
                "AZURE_TENANT_ID",
                "AZURE_CLIENT_ID",
                "AZURE_CLIENT_SECRET",
                "STORAGE_ACCOUNT_NAME",
            )
        ),
    }

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


def _collect_scan(args: argparse.Namespace):
    catalog = (
        load_rule_catalog(args.rules) if args.rules else load_default_rule_catalog()
    )
    if args.source == "fixture":
        states = _fixture_states(args.fixture, args.service)
    else:
        states = _azure_states(args.service)
    findings = evaluate_states(states, catalog)
    return states, findings


def _scan_document(states, findings, *, cycle: int | None = None) -> dict:
    document = {
        "summary": {
            "resources": len(states),
            "findings": len(findings),
        },
        "findings": [finding.to_dict() for finding in findings],
    }
    if cycle is not None:
        document["cycle"] = cycle
    return document


def _emit_text(states, findings) -> None:
    print(f"Scanned {len(states)} resource(s); {len(findings)} finding(s).")
    for finding in findings:
        print(
            f"[{finding.severity}] {finding.rule_id} "
            f"{finding.resource.name}: {finding.title}"
        )


def _run_scan(args: argparse.Namespace) -> int:
    states, findings = _collect_scan(args)
    if args.format == "json":
        print(json.dumps(_scan_document(states, findings), indent=2))
    else:
        _emit_text(states, findings)
    return EXIT_FINDINGS if findings else EXIT_OK


def _run_watch(args: argparse.Namespace) -> int:
    cycle = 1
    had_findings = False
    while True:
        states, findings = _collect_scan(args)
        had_findings = had_findings or bool(findings)
        if args.format == "jsonl":
            print(json.dumps(_scan_document(states, findings, cycle=cycle)))
        else:
            _emit_text(states, findings)

        if args.iterations is not None and cycle >= args.iterations:
            return EXIT_FINDINGS if had_findings else EXIT_OK
        time.sleep(args.interval)
        cycle += 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "doctor":
            return _run_doctor(args.format)
        if args.command == "watch":
            return _run_watch(args)
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
