# SLATE — Chain of Custody

## Item lifecycle

```
intake → [transfers] → [access events] → [legal hold set/release] → [export] → [destroyed]
```

Each transition generates a `CustodyEvent` written to the tamper-evident audit log.

## CustodyEvent types

| Event type | Trigger | Log level |
|------------|---------|-----------|
| `intake` | New item recorded | INFO |
| `transfer` | Custody transferred | INFO |
| `access` | Item examined | INFO |
| `hold_set` | Legal hold placed | WARN |
| `hold_release` | Legal hold removed | INFO |
| `export` | Court bundle generated | INFO |
| `destroyed` | Item destroyed | WARN |

## CustodyEvent fields

```json
{
  "item_id":    "EV-20260512-a3b2c1d0",
  "case_number": "CASE-2026-0042",
  "event_type": "transfer",
  "timestamp":  "2026-05-12T14:23:01Z",
  "actor":      "Clerk Rivera",
  "actor_role": "evidence_clerk",
  "from_node":  "evidence-room-1",
  "to_node":    "forensics-lab",
  "notes":      "Transfer for DNA analysis",
  "bundle_ref": "XFER-20260512-9f2a1c3d"
}
```

**`actor` is always from the authenticated token** — not user-supplied input. Every log entry is traceable to a specific token, role, and name.

### Schema additions in v1.1 (backward compatible)

Two optional fields were added to `CustodyEvent`, both `omitempty`:

| Field | Meaning |
|-------|---------|
| `actor_role` | The role bound to the acting token. Recorded on events from v1.1 onward; **empty on pre-v1.1 events**. |
| `bundle_ref` | The inter-node transfer bundle ID (present on cross-node handoff events). |

**Migration note:** these are purely additive. Existing logs remain valid and
verify unchanged — every entry stores its own `prev_hash`, and adding `omitempty`
fields does not alter the serialization of records that don't set them. The
`slate audit query --role` filter only matches events that carry `actor_role`
(i.e. those recorded at or after v1.1); older events have no role to match.

## Item ID format

```
EV-YYYYMMDD-XXXXXXXX
```

`XXXXXXXX` = 4 bytes of cryptographic random hex. Example: `EV-20260512-a3b2c1d0`.

## Legal hold enforcement

Legal holds are enforced in code, not just policy:

- `RecordTransfer` returns an error and refuses to proceed if `item.LegalHold == true`
- `RecordDestroyed` returns an error and refuses to proceed if `item.LegalHold == true`
- Both the catalog (`items.json`) and the log record the hold state independently

## Hash chain integrity

The log is SHA-256 hash-chained: each entry includes `prev_hash` = SHA-256 of the previous entry's plaintext JSON. Any modification, deletion, or insertion breaks the chain.

To verify chain integrity:
```bash
slate verify          # or: slate verify --json
```

`slate verify` walks the log record by record and checks that:

- every record decrypts under the node's key (else the ciphertext was altered),
- sequence numbers are strictly `1,2,3,…` (else a record was inserted or removed),
- each record's `prev_hash` equals SHA-256 of the previous record's plaintext
  (else a record's contents were altered or dropped).

It reports the first break found and exits non-zero. **Scope of the guarantee:**
the hash chain proves no *partial* edit. A holder of the machine-bound key who
rewrites the *entire* log cannot be caught by the chain alone — that is what the
Ed25519-signed export bundles (an external anchor) are for.
