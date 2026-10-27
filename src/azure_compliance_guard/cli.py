import argparse
import json
import math
import os
import sys
import time
from datetime import UTC, datetime, timedelta
from importlib.resources import as_file, files
from pathlib import Path
from uuid import uuid4

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
from azure_compliance_guard.evidence import append_events, make_event, read_events
from azure_compliance_guard.exceptions import ExceptionRepository
from azure_compliance_guard.incident import (
    TrustedNetworks,
    process_incidents,
    verify_containment,
)
from azure_compliance_guard.monitor import (
    make_logs_client,
    normalize_storage_rows,
    query_storage_events,
)
from azure_compliance_guard.remediation import (
    AzureExecutor,
    InvalidPlanError,
    apply_plan,
    approve_plan,
    create_plan,
    has_active_exception_db,
    read_approval,
    read_plan,
)
from azure_compliance_guard.report import render_report
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


def _add_scan_arguments(
    parser: argparse.ArgumentParser, *, allow_fixture_path: bool = False
) -> None:
    parser.add_argument(
        "--source",
        choices=None if allow_fixture_path else ("azure", "fixture"),
        default="azure",
    )
    parser.add_argument(
        "--service",
        choices=("storage", "key-vault", "sql", "all"),
        default=None if allow_fixture_path else "storage",
    )
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--rules", type=Path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="acg", description="Azure Compliance Guard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="check local runtime readiness")
    doctor.add_argument("--format", choices=("text", "json"), default="text")

    scan = subparsers.add_parser("scan", help="run one compliance scan and exit")
    _add_scan_arguments(scan, allow_fixture_path=True)
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("--output", type=Path, help="append schema-v1 JSONL evidence")

    report = subparsers.add_parser("report", help="render a public offline HTML report")
    report.add_argument("--input", required=True, type=Path)
    report.add_argument("--output", required=True, type=Path)
    report.add_argument(
        "--redact", action="store_true", help="public redaction (always enabled)"
    )

    watch = subparsers.add_parser("watch", help="run compliance scans repeatedly")
    _add_scan_arguments(watch)
    watch.add_argument("--format", choices=("text", "jsonl"), default="text")
    watch.add_argument("--interval", type=_positive_float, default=60.0)
    watch.add_argument("--iterations", type=_positive_int)

    remediation = subparsers.add_parser(
        "remediation", help="plan and control remediation"
    )
    remediation_commands = remediation.add_subparsers(
        dest="remediation_command", required=True
    )
    plan = remediation_commands.add_parser(
        "plan", help="create a JSON plan without mutation"
    )
    _add_scan_arguments(plan)
    plan.add_argument("--finding", required=True, help="finding ID or unique rule ID")
    plan.add_argument("--resource", help="resource name if the finding is ambiguous")
    plan.add_argument("--output", type=Path, help="create a new plan file")

    approve = remediation_commands.add_parser("approve", help="approve one exact plan")
    approve.add_argument("--plan", required=True, type=Path)
    approve.add_argument("--approver", required=True)
    approve.add_argument("--confirm-hash", required=True)
    approve.add_argument("--output", type=Path, help="create a new approval file")

    apply = remediation_commands.add_parser("apply", help="dry-run or execute one plan")
    apply.add_argument("--plan", required=True, type=Path)
    apply.add_argument("--approval", type=Path)
    apply.add_argument(
        "--exceptions-db", type=Path, help="reviewed SQLite exception store"
    )
    apply.add_argument("--rules", type=Path)
    mode = apply.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")

    exceptions = subparsers.add_parser("exception", help="govern SQLite exceptions")
    exception_commands = exceptions.add_subparsers(
        dest="exception_command", required=True
    )
    for name in (
        "init",
        "request",
        "activate",
        "expire",
        "revoke",
        "list",
        "verify-chain",
    ):
        command = exception_commands.add_parser(name)
        command.add_argument("--db", required=True, type=Path)
        if name == "request":
            for field in (
                "resource-id",
                "resource-name",
                "rule-id",
                "owner",
                "reason",
                "ticket",
            ):
                command.add_argument(f"--{field}", required=True)
            command.add_argument("--minutes", type=_positive_int, required=True)
        if name in {"activate", "expire", "revoke"}:
            command.add_argument("--id", required=True)
            command.add_argument(
                "--expected-version", type=_positive_int, required=True
            )
        if name == "activate":
            command.add_argument("--approved-by", required=True)
        if name == "revoke":
            command.add_argument("--actor", required=True)
            command.add_argument("--reason", required=True)
            command.add_argument("--incident", action="store_true")
        if name == "list":
            command.add_argument(
                "--status", choices=("REQUESTED", "ACTIVE", "EXPIRED", "REVOKED")
            )
            command.add_argument("--resource-id")

    incident = subparsers.add_parser("incident", help="evaluate Storage log incidents")
    incident_commands = incident.add_subparsers(dest="incident_command", required=True)
    incident_scan = incident_commands.add_parser(
        "scan", help="query Blob logs or an offline monitor fixture"
    )
    incident_scan.add_argument(
        "--source", choices=("azure", "fixture"), default="azure"
    )
    incident_scan.add_argument("--fixture", type=Path)
    incident_scan.add_argument("--workspace-id")
    incident_scan.add_argument("--account", required=True)
    incident_scan.add_argument("--resource-id", required=True)
    incident_scan.add_argument("--lookback-minutes", type=_positive_int, default=45)
    incident_scan.add_argument("--trusted-cidr", action="append", required=True)
    incident_scan.add_argument("--exceptions-db", required=True, type=Path)
    incident_scan.add_argument("--state-db", required=True, type=Path)
    incident_scan.add_argument("--evidence", required=True, type=Path)
    incident_verify = incident_commands.add_parser(
        "verify", help="re-collect Storage state after approved containment"
    )
    incident_verify.add_argument(
        "--source", choices=("azure", "fixture"), default="azure"
    )
    incident_verify.add_argument("--fixture", type=Path)
    incident_verify.add_argument("--resource-id", required=True)
    incident_verify.add_argument("--event-key", required=True)
    incident_verify.add_argument("--evidence", required=True, type=Path)
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
    if args.source == "azure":
        states = _azure_states(args.service or "storage")
    elif args.source == "fixture":
        states = _fixture_states(args.fixture, args.service or "storage")
    elif args.command == "scan":
        path = Path(args.source)
        if path.suffix.lower() != ".json" or not path.is_file():
            raise InvalidRuleSetError(
                "--source must be azure, fixture, or an existing JSON fixture"
            )
        states = _fixture_states(path, args.service or "all")
    else:
        raise InvalidRuleSetError("invalid scan source")
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
    run_id = str(uuid4())
    source = {
        "mode": "azure" if args.source == "azure" else "fixture",
        "collector": args.service
        or ("all" if args.source not in {"azure", "fixture"} else "storage"),
        "catalog_version": 1,
    }
    started_at = datetime.now(UTC)
    started = time.perf_counter()
    if args.output:
        append_events(
            args.output,
            [
                make_event(
                    "RUN_STARTED",
                    run_id=run_id,
                    resource=None,
                    source=source,
                    data={},
                    now=started_at,
                )
            ],
        )
    try:
        states, findings = _collect_scan(args)
    except Exception as exc:
        if args.output:
            append_events(
                args.output,
                [
                    make_event(
                        "RUN_COMPLETED",
                        run_id=run_id,
                        resource=None,
                        source=source,
                        data={
                            "status": "ERROR",
                            "error_type": type(exc).__name__,
                            "duration_ms": round(
                                (time.perf_counter() - started) * 1000
                            ),
                        },
                    )
                ],
            )
        raise
    if args.output:
        catalog = (
            load_rule_catalog(args.rules) if args.rules else load_default_rule_catalog()
        )
        evaluated = sum(
            rule.service == state.resource.service
            for state in states
            for rule in catalog.rules
        )
        events = [
            make_event(
                "FINDING",
                run_id=run_id,
                resource=finding.resource.to_dict(),
                source=source,
                data={
                    key: value
                    for key, value in finding.to_dict().items()
                    if key != "resource"
                },
            )
            for finding in findings
        ]
        events.append(
            make_event(
                "RUN_COMPLETED",
                run_id=run_id,
                resource=None,
                source=source,
                data={
                    "status": "COMPLETED",
                    "resources_scanned": len(states),
                    "rules_evaluated": evaluated,
                    "findings": len(findings),
                    "duration_ms": round((time.perf_counter() - started) * 1000),
                },
            )
        )
        append_events(args.output, events)
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


def _read_artifact(path: Path) -> object:
    if path.stat().st_size > 1_048_576:
        raise InvalidPlanError("artifact exceeds 1 MiB")
    return json.loads(path.read_text(encoding="utf-8"))


def _emit_artifact(document: dict, output: Path | None) -> None:
    encoded = json.dumps(document, indent=2) + "\n"
    if output is None:
        print(encoded, end="")
    else:
        with output.open("x", encoding="utf-8") as artifact:
            artifact.write(encoded)
        print(f"Created {output}")


def _run_remediation_plan(args: argparse.Namespace) -> int:
    states, findings = _collect_scan(args)
    matches = [
        finding
        for finding in findings
        if args.finding in {finding.finding_id, finding.rule_id}
        and (args.resource is None or finding.resource.name == args.resource)
    ]
    if len(matches) != 1:
        raise InvalidPlanError("--finding must identify exactly one current finding")
    finding = matches[0]
    state = next(state for state in states if state.resource == finding.resource)
    catalog = (
        load_rule_catalog(args.rules) if args.rules else load_default_rule_catalog()
    )
    rule = next(rule for rule in catalog.rules if rule.id == finding.rule_id)
    plan = create_plan(finding, state, rule, source=args.source)
    _emit_artifact(plan.to_dict(), args.output)
    return EXIT_OK


def _run_remediation_approve(args: argparse.Namespace) -> int:
    plan = read_plan(_read_artifact(args.plan))
    if args.confirm_hash != plan.plan_hash:
        raise InvalidPlanError("confirmed hash does not match the plan")
    approval = approve_plan(plan, args.approver)
    _emit_artifact(approval.to_dict(), args.output)
    return EXIT_OK


def _run_remediation_apply(args: argparse.Namespace) -> int:
    plan = read_plan(_read_artifact(args.plan))
    catalog = (
        load_rule_catalog(args.rules) if args.rules else load_default_rule_catalog()
    )
    if args.dry_run:
        result = apply_plan(
            plan,
            approval=None,
            catalog=catalog,
            collect=lambda: None,
            execute=lambda _plan: False,
            has_active_exception=lambda _plan: False,
            dry_run=True,
        )
    else:
        if plan.source != "azure":
            raise InvalidPlanError("execution requires a live Azure plan")
        if os.getenv("ALLOW_AZURE_MUTATIONS", "").strip().lower() != "true":
            raise InvalidPlanError(
                "ALLOW_AZURE_MUTATIONS=true is required for execution"
            )
        if args.approval is None:
            raise InvalidPlanError("--approval is required for execution")
        if args.exceptions_db is None:
            raise InvalidPlanError("--exceptions-db is required for execution")
        if plan.resource.get("subscription_id") != os.getenv("AZURE_SUBSCRIPTION_ID"):
            raise InvalidPlanError(
                "plan subscription does not match current configuration"
            )
        approval = read_approval(_read_artifact(args.approval))
        service = {"storage": "storage", "key_vault": "key-vault", "sql": "sql"}[
            plan.resource["service"]
        ]

        def collect():
            states = _azure_states(service)
            if len(states) != 1:
                raise RuntimeError("expected exactly one Azure resource")
            return states[0]

        if service == "storage":
            required = _required_environment(
                (
                    "AZURE_TENANT_ID",
                    "AZURE_CLIENT_ID",
                    "AZURE_CLIENT_SECRET",
                )
            )
            from azure.identity import ClientSecretCredential
            from azure.mgmt.storage import StorageManagementClient

            credential = ClientSecretCredential(
                tenant_id=required["AZURE_TENANT_ID"],
                client_id=required["AZURE_CLIENT_ID"],
                client_secret=required["AZURE_CLIENT_SECRET"],
            )
            executor = AzureExecutor(
                storage_client=StorageManagementClient(
                    credential,
                    plan.resource["subscription_id"],
                    connection_timeout=10,
                    read_timeout=60,
                    retry_total=2,
                )
            )
        else:
            executor = AzureExecutor(
                cli_runner=AzureCliJsonRunner(plan.resource["subscription_id"])
            )
        result = apply_plan(
            plan,
            approval=approval,
            catalog=catalog,
            collect=collect,
            execute=executor.execute,
            has_active_exception=lambda current: has_active_exception_db(
                current, args.exceptions_db
            ),
        )
    print(json.dumps(result.to_dict()))
    return (
        EXIT_OK if result.status in {"DRY_RUN", "VERIFIED"} else EXIT_OPERATIONAL_ERROR
    )


def _run_exception(args: argparse.Namespace) -> int:
    repo = ExceptionRepository(args.db)
    command = args.exception_command
    if command == "init":
        repo.initialize()
        result = {"database": str(args.db), "schema_version": 1}
    elif command == "request":
        result = repo.request(
            resource_id=args.resource_id,
            resource_name=args.resource_name,
            rule_id=args.rule_id,
            owner=args.owner,
            reason=args.reason,
            ticket=args.ticket,
            expires_at=datetime.now(UTC) + timedelta(minutes=args.minutes),
        ).to_dict()
    elif command == "activate":
        result = repo.activate(
            args.id,
            approved_by=args.approved_by,
            expected_version=args.expected_version,
        ).to_dict()
    elif command == "expire":
        result = repo.expire(args.id, expected_version=args.expected_version).to_dict()
    elif command == "revoke":
        result = repo.revoke(
            args.id,
            actor=args.actor,
            reason=args.reason,
            expected_version=args.expected_version,
            incident=args.incident,
        ).to_dict()
    elif command == "list":
        result = [
            record.to_dict()
            for record in repo.list(status=args.status, resource_id=args.resource_id)
        ]
    else:
        result = {"events": repo.verify_chain(), "valid": True}
    print(json.dumps(result, indent=2))
    return EXIT_OK


def _run_report(args: argparse.Namespace) -> int:
    html = render_report(read_events(args.input))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(html)
    print(f"Created {args.output}")
    return EXIT_OK


def _run_incident(args: argparse.Namespace) -> int:
    policy = TrustedNetworks(args.trusted_cidr)
    if args.source == "fixture":
        if args.fixture is None or args.workspace_id is not None:
            raise ValueError("fixture source requires --fixture and no workspace ID")
        if args.fixture.stat().st_size > 1_048_576:
            raise ValueError("monitor fixture exceeds 1 MiB")
        document = json.loads(args.fixture.read_text(encoding="utf-8"))
        if (
            not isinstance(document, dict)
            or set(document) != {"columns", "rows"}
            or not isinstance(document["columns"], list)
            or not isinstance(document["rows"], list)
        ):
            raise ValueError("monitor fixture must contain columns and rows")
        events = normalize_storage_rows(
            document["columns"], document["rows"], args.account, args.resource_id
        )
    else:
        if args.fixture is not None or not args.workspace_id:
            raise ValueError("Azure source requires --workspace-id and no fixture")
        client = make_logs_client()
        try:
            events = query_storage_events(
                client,
                args.workspace_id,
                args.account,
                args.resource_id,
                args.lookback_minutes,
            )
        finally:
            client.close()
    result = process_incidents(
        events,
        policy,
        ExceptionRepository(args.exceptions_db),
        args.state_db,
        args.evidence,
        mode=args.source,
    )
    findings = sum(item["severity"] != "NORMAL" for item in result)
    print(
        json.dumps(
            {
                "source": args.source,
                "queried": len(events),
                "processed": len(result),
                "escalated": sum(
                    item["severity"] == "ESCALATED_CRITICAL" for item in result
                ),
                "results": result,
            },
            indent=2,
        )
    )
    return EXIT_FINDINGS if findings else EXIT_OK


def _run_incident_verify(args: argparse.Namespace) -> int:
    if args.source == "fixture":
        if args.fixture is None:
            raise ValueError("fixture verification requires --fixture")
        states = FixtureStorageCollector(args.fixture).collect()
    else:
        if args.fixture is not None:
            raise ValueError("Azure verification does not accept a fixture")
        states = _azure_states("storage")
    if len(states) != 1:
        raise ValueError("verification requires exactly one Storage resource")
    result = verify_containment(
        args.event_key,
        args.resource_id,
        states[0],
        args.evidence,
        mode=args.source,
    )
    print(json.dumps({"event_key": args.event_key, "verification": result}))
    return EXIT_OK if result == "VERIFIED" else EXIT_FINDINGS


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "doctor":
            return _run_doctor(args.format)
        if args.command == "watch":
            return _run_watch(args)
        if args.command == "exception":
            return _run_exception(args)
        if args.command == "incident":
            return (
                _run_incident_verify(args)
                if args.incident_command == "verify"
                else _run_incident(args)
            )
        if args.command == "report":
            return _run_report(args)
        if args.command == "remediation":
            if args.remediation_command == "plan":
                return _run_remediation_plan(args)
            if args.remediation_command == "approve":
                return _run_remediation_approve(args)
            return _run_remediation_apply(args)
        return _run_scan(args)
    except (InvalidRuleSetError, InvalidPlanError) as exc:
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
