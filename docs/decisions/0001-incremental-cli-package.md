# ADR-001: Migrate to the CLI package by vertical slice

## Status

Accepted

## Date

2026-10-23

## Context

The existing monitor is a continuously running set of flat Python modules with
dictionary-shaped collector output and hard-coded policy decisions. Phase E
requires an installable CLI, typed boundaries, and versioned rules without
breaking the already-tested safety behavior.

## Decision

Add an installable `src/azure_compliance_guard` package one service slice at a
time. The first slice is a one-shot Storage scan: both fixture and Azure SDK
collectors produce `StorageState`, and an Azure-independent evaluator consumes a
validated schema-v1 YAML catalog. Keep the legacy monitor operational until each
remaining service/workflow has its own tested replacement.

## Alternatives considered

- Big-bang rewrite: rejected because it would combine packaging, collector,
  evaluator, monitoring, incident, exception, and remediation risks in one move.
- Wrap the legacy dictionary evaluator directly: rejected because it would keep
  source-specific shapes coupled to policy conclusions and make the YAML schema
  cosmetic rather than authoritative.

## Consequences

- The repository temporarily contains a legacy engine and a new package.
- Storage has stable rule IDs and typed facts; Key Vault/SQL remain explicitly
  deferred rather than represented by speculative models.
- CLI scanning is composable and exits; continuous watch behavior must be a
  separate command later.
- External benchmark mappings remain unverified and cannot be inferred from rule
  titles.
