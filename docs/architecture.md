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
