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
  "from_node":  "evidence-room-1",
  "to_node":    "forensics-lab",
  "notes":      "Transfer for DNA analysis"
}
```

**`actor` is always from the authenticated token** — not user-supplied input. Every log entry is traceable to a specific token, role, and name.

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
# Placeholder — chain verification command planned for SLATE v1.1
# slate verify
```
