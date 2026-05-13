# SLATE — Overview

**Secure Log Audit for Trace Evidence**

SLATE is a standalone, tamper-evident chain-of-custody evidence management system for law enforcement. It runs as a single Go binary on a local department-controlled node. No cloud account required. No external services.

## What SLATE does

- Records evidence intake with a unique item ID and case number
- Logs every custody transfer with full from-node/to-node chain
- Enforces legal holds — transfer and destruction are hard-blocked while a hold is active
- Generates signed, tamper-evident court export bundles (NDJSON + optional Ed25519 signature)
- Serves a local 5-tab dashboard over HTTP, accessible to role-based tokens
- Encrypts all audit log entries with AES-256-GCM using a machine-ID-derived key

## What SLATE does NOT do

- Connect to the internet during normal operation
- Allow the audit log to be modified (append-only by design)
- Transfer or destroy evidence while a legal hold is active
- Accept actor names from unauthenticated sources (actor = authenticated token name)

## Core design principles

1. **Simple** — one binary, standard HTTP, vanilla HTML/JS dashboard, no runtime deps
2. **Tamper-evident** — SHA-256 hash-chained entries; any modification breaks the chain
3. **KISS** — clear tabs, clear roles, clear logs, clear exports, clear node boundaries
4. **Court-defensible** — actor in every log entry comes from the authenticated token, not user input
5. **Offline-first** — works on an air-gapped node; no cloud dependency

## Product lineage

SLATE is the law enforcement edition of the [Harborlight](https://github.com/bigblue-r4/kiss-protocol) stack by SGAIL Labs. It shares the core encrypted log and soul file identity layer, with separate key derivation (the two systems' logs cannot cross-decrypt on the same machine).
