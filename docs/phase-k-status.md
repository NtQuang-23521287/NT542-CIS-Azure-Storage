# Phase K status

The branch prepares the cost-safe demo offline. It has **not** deployed, queried, mutated or destroyed Azure resources for Phase K.

## Prepared

- Isolated `azure-minimal-storage` Terraform root with dedicated RG naming, six lifecycle tags, Storage, Log Analytics and Blob diagnostics. The original `azure-secure-storage` root remains the full demo with its existing Terraform resource addresses.
- Offline CI validates both Terraform roots and scans the Terraform directory. Minimal provider lockfile is pinned to AzureRM 3.117.1.
- [Demo and cleanup runbook](demo.md), [architecture](architecture.md), [threat model](threat-model.md), [controls](controls.md) and README describe the intended flow and its limits.

## Open acceptance work

1. Review the actual Azure account's credit, prices, budget options, region and quota; choose the new RG, state key, owner and expiry. The backend container and least-privilege identities must be ready.
2. Review a minimal Terraform plan, apply in the dedicated lab, run an ARM Storage scan and a controlled drift/remediation demonstration if separately approved.
3. Review the destroy plan, destroy only the dedicated lab resources, and verify the RG is absent. Save private evidence of the apply and cleanup.
4. If a real Blob incident is part of the demonstration, first design a private data-plane path and verify actual `StorageBlobLogs` ingestion. The default minimal root intentionally has no path for laptop Blob operations.

Offline Terraform validation cannot confirm SKU availability, Azure quota, current pricing, Log Analytics ingestion or successful cleanup. Checkpoint K remains open until the live steps have evidence.
