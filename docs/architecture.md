# SLATE — Architecture

## Component map

```
cmd/slate/main.go
│
├── internal/evidence      — Item catalog + custody event recording
│   └── internal/store     — Encrypted, hash-chained append-only log
│       └── internal/encrypt — AES-256-GCM (SLATE-specific HKDF label)
│
├── internal/roles         — RBAC definitions and Can(role, perm) checks
├── internal/tokens        — Token registry (tokens.json); maps token → role+name
├── internal/export        — Court export bundle generation and Ed25519 signing
│   └── internal/store     — Read log entries for bundle
│
├── internal/soul          — Identity verification (soul.toml)
└── internal/machid        — Stable machine identifier for key derivation
```

## Key derivation

The SLATE AES-256-GCM log key is derived from the machine ID using HKDF-SHA256 with SLATE-specific salt and info:

```
key = HKDF-SHA256(
    secret = machine_id,
    salt   = "slate-kdf-salt-2026",
    info   = "slate-aes256-gcm-v1"
)
```

This produces a different key from the general Harborlight witness (`"witness-aes256-gcm-v1"`). The two systems' logs cannot cross-decrypt, even on the same machine.

## Evidence storage

Two layers work together:

**Encrypted audit log** (`~/.slate/primary/witness.log`):
- Append-only, AES-256-GCM encrypted, SHA-256 hash-chained
- Each record: `[uint32 length][nonce || ciphertext]`
- Decrypted payload: `store.Entry` JSON with `seq`, `ts`, `level`, `event`, `source`, `prev_hash`, `data`
- `data` is a `CustodyEvent` JSON payload with `case_number` embedded for export filtering

**Truncation anchor** (`~/.slate/primary/log-head.json`):
- `{ seq, tip_hash, prev_head, ts, sig, signer_key }`, rewritten on every append
- Exists because the hash chain cannot see a truncation. Drop the last N records and what remains
  is a shorter chain in which every `prev_hash` still lines up and `seq` still counts from 1 —
  nothing *inside* the log records how long the log is meant to be. The anchor records it outside.
- Signed with the node's Ed25519 identity key, the same key used for discovery announcements and
  sealed transfers, resolved via `resolveNodeKey` (env `SLATE_NODE_KEY`, else the machine-bound
  `nodekey.enc`). No separate key, no extra key management.
- `prev_head` is the SHA-256 of the previous head file's raw bytes, so successive heads form their
  own chain
- Written temp-file-then-rename, and written *after* the record reaches the log. A crash between
  the two leaves a head that is behind the log ("stale"), never one claiming records the log does
  not hold — stale is recoverable and honest, over-claiming would be indistinguishable from
  truncation.
- **Logs with no anchor are not failures.** Every log written before this existed has none;
  `slate verify` reports "not anchored" and exits 0.

**What the anchor does not do.** The node signs its own head with a key on the same machine as the
log, so root on the node can truncate and re-sign. This is not tamper-proofing. It gives detection
to an observer holding an earlier head — the `prev_head` chain means a substituted head cannot be
slid into a sequence someone else has already seen, which is what makes the peer and export paths
useful as witnesses rather than just transports. Proving one item's custody history *without*
disclosing the rest of the log is a different property again; that needs a Merkle tree and is not
attempted here.

**Evidence catalog** (`~/.slate/primary/items.json`):
- Mutable JSON — current state of all items
- Updated atomically on each mutation, protected by a mutex
- Provides fast item lookup without replaying the log

## HTTP API (role-gated)

Every `/api/*` route is protected by `require(perm)` middleware:

1. Reads `Authorization: Bearer <token>` header
2. Reloads `tokens.json` from disk (supports live token revocation without restart)
3. Looks up the token — 401 if not found
4. Calls `roles.Can(role, perm)` — 403 if insufficient permission
5. Stores the `tokens.Entry` in the request context
6. All downstream handlers read `actorFrom(r)` to get the actor name for audit logs

The actor in every audit log entry comes from the authenticated token's name — not from user-supplied request fields. This makes every log entry court-traceable to a specific token and role.

## Dashboard security

- Served on `127.0.0.1` only (loopback)
- Login screen stores the Bearer token in `sessionStorage`
- After login, `/api/whoami` returns the role and full permission map
- The dashboard hides or disables UI elements the role cannot use
- All server-side API calls still enforce permissions regardless of client-side UI state
