# SLATE — Court Export Bundles

## Purpose

Court export bundles are tamper-evident packages of the complete chain of custody for a case, suitable for disclosure in legal proceedings.

## Format: NDJSON

Bundles are written as newline-delimited JSON (one JSON object per line):

- **Line 1**: Bundle header (metadata, chain hash, optional signature)
- **Lines 2–N**: One audit log entry per line

## Bundle header

```json
{
  "bundle_id":    "BUNDLE-20260512-a3b2c1d0",
  "generated_at": "2026-05-12T14:30:00Z",
  "case_number":  "CASE-2026-0042",
  "department":   "Honolulu PD",
  "node_id":      "node-001",
  "entry_count":  7,
  "sha256_chain": "e3b0c44298fc1c149afbf4c…",
  "signature":    "<optional Ed25519 hex signature>"
}
```

## Generating a bundle

```bash
# Without signature
slate export --case CASE-2026-0042

# With Ed25519 signature
export SLATE_SIGN_KEY=<private-key-hex>
slate export --case CASE-2026-0042 --sign
```

Or from the dashboard: **Tech / Admin → Generate Court Export**.

Output: `~/.slate/exports/BUNDLE-YYYYMMDD-XXXXXXXX.ndjson`

## SHA-256 chain hash

`sha256_chain` = SHA-256 of all included entry JSON payloads, concatenated in order. Verifying this hash confirms the bundle content was not modified after generation.

## Ed25519 signing

```bash
# Generate a key pair
slate keygen
# → prints public key (store in config) and private key (keep secret)

# Export and sign
export SLATE_SIGN_KEY=<private-key-hex>
slate export --case CASE-2026-0042 --sign
```

The signature covers all bundle fields except the `signature` field itself (zeroed before signing). Verification:

```go
err := export.Verify(bundle, publicKeyHex)
```

## What is included

Only log entries with `data.case_number == <requested case>` are included. System-level events are excluded.

## Export audit trail

Every `slate export` call automatically appends a `slate/export` event to the audit log for each item in the case, recording the actor name and bundle ID. The export itself is part of the custody chain.

## Retention

Export bundles are plain NDJSON files on disk. Back them up to a separate location as part of your evidence retention policy. The encrypted audit log is the authoritative source; bundles are derived exports from it.
