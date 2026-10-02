from __future__ import annotations

from config import (
    SENSITIVE_KEYVAULT_OPERATIONS,
    SENSITIVE_SQL_OPERATIONS,
    SENSITIVE_STORAGE_OPERATIONS,
)


ESCALATED_CRITICAL = "ESCALATED_CRITICAL"


def _issue(name: str, service: str, signal: dict) -> dict:
    return {
        "name": name,
        "severity": ESCALATED_CRITICAL,
        "service": service,
        "evidence": {
            "source_ip": signal.get("source_ip", "unknown"),
            "identity": signal.get("identity", "unknown"),
            "operation": signal.get("operation", "unknown"),
            "result": signal.get("result", "unknown"),
            "details": signal.get("details", ""),
        },
    }


def _is_successful_sensitive_access(signal: dict, sensitive_operations: set[str]) -> bool:
    return (
        signal.get("untrusted_source") is True
        and str(signal.get("result", "")).lower() == "success"
        and signal.get("operation") in sensitive_operations
    )


def evaluate_storage_incidents(signals: list[dict]) -> tuple[bool, list[dict]]:
    issues = [
        _issue("Storage sensitive access from untrusted source", "storage", signal)
        for signal in signals
        if _is_successful_sensitive_access(signal, SENSITIVE_STORAGE_OPERATIONS)
    ]
    return bool(issues), issues


def evaluate_key_vault_incidents(signals: list[dict]) -> tuple[bool, list[dict]]:
    issues = [
        _issue("Key Vault secret access from untrusted source", "key_vault", signal)
        for signal in signals
        if _is_successful_sensitive_access(signal, SENSITIVE_KEYVAULT_OPERATIONS)
    ]
    return bool(issues), issues


def evaluate_sql_incidents(signals: list[dict]) -> tuple[bool, list[dict]]:
    issues = [
        _issue("SQL suspicious successful login", "sql", signal)
        for signal in signals
        if _is_successful_sensitive_access(signal, SENSITIVE_SQL_OPERATIONS)
    ]
    return bool(issues), issues
