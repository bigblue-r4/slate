# SLATE — Secure Log Audit for Trace Evidence

Tamper-evident chain-of-custody evidence management for law enforcement.

SLATE runs on a local department-controlled node. No cloud required. Encrypted, hash-chained audit log. Role-based access. Ed25519-signed court export bundles.

## Quick start

```bash
# 1. Build
go build -o slate ./cmd/slate

# 2. Initialize
./slate init --department "Honolulu PD" --node "node-001"

# 3. Add your first access token
./slate token add --role chief --name "Chief Johnson"
# → prints a token; copy it now

# 4. Start the dashboard
./slate serve
# → http://127.0.0.1:8890
```

## CLI reference

```
slate init       [--department NAME] [--node ID]
slate status
slate intake     --case C --desc D [--cat CATEGORY] [--node NODE] [--role ROLE]
slate transfer   --item ID --from NODE --to NODE [--notes TEXT]
slate hold set   --item ID --reason TEXT
slate hold release --item ID
slate export     --case C [--sign]
slate audit query [--case C] [--item ID] [--type EVENT] [--role R] [--actor N] [--from DATE] [--to DATE] [--text S]
slate import     --file PATH [--format csv|json] [--dry-run]
slate batch      transfer --to NODE (--items a,b,c | --case C | --category CAT)
slate batch      hold set|release (--items a,b,c | --case C) [--reason TEXT]
slate verify
slate peer       keygen | identity | add | list | remove | transfer
slate token add  --role ROLE --name NAME
slate token list
slate token revoke TOKEN
slate keygen
slate serve      [--port 8890] [--peer-listen HOST:PORT]
slate version
```

**Every command accepts `--json`** for stable, schema-versioned output. This is
the same contract the dashboard consumes — there is no separate data path.

### JSON contract (`slate.v1`)

```json
{ "schema": "slate.v1", "ok": true,  "data": <payload> }
{ "schema": "slate.v1", "ok": false, "error": { "code": "...", "message": "..." } }
```

The REST API served by `slate serve` returns the identical envelope. New optional
fields may be added to a payload without a schema bump; a breaking change to an
existing field would bump the schema to `slate.v2`.

### Bulk import

CSV (header row) or JSON array. Columns/keys: `case`/`case_number`,
`description`/`desc`, `category`/`cat`, `node`. The batch is **atomic on
validation** — every row is validated first, and if any row is invalid nothing is
written. `--dry-run` validates without writing.

### Chain verification

```bash
slate verify          # walks the log, recomputes the hash chain, reports the first break
```

Exits non-zero if the chain is broken.

## Multi-node LAN custody (v1.1)

Transfer custody of an item to a peer node over a department LAN, offline, with
the audit chain intact across the handoff. **Manual pairing only** — no
auto-discovery. See [`docs/node-model.md`](docs/node-model.md) for the full trust
model.

```bash
# On each node, once: generate an identity key (kept ONLY in the env, never on disk)
slate peer keygen                    # prints public + private key
export SLATE_NODE_KEY=<private-hex>

# Exchange public keys out of band, then enroll each other
slate peer add --node node-B --pubkey <B-pubkey> --addr 192.168.1.20:8891

# Receiver enables the LAN peer listener (the ONLY bind beyond 127.0.0.1)
slate serve --peer-listen 0.0.0.0:8891

# Sender hands off an item; the receiver verifies the signature before accepting
slate peer transfer --item EV-... --to node-B
```

A handoff is a **signed transfer bundle** (Ed25519). The receiver verifies the
signature against the *enrolled* public key for the claimed sender before
accepting anything; an unknown sender, a bad signature, or a mutated bundle is
rejected and logged. Both nodes record the handoff in their audit logs.

## Roles

| Role | What they can do |
|------|-----------------|
| `chief` | Everything |
| `evidence_clerk` | Intake, transfer, holds |
| `tech_admin` | System admin, audit read |
| `officer` | Intake, status |
| `auditor` | Read-only audit trail |

## Data layout

```
~/.slate/
├── soul.toml      — immutable identity (verified at startup)
├── config.json    — department, node ID, port
├── tokens.json    — per-role access tokens
├── peers.json     — enrolled peer nodes (public keys + addresses) [v1.1]
├── primary/       — encrypted audit log + evidence catalog
└── exports/       — generated court export bundles (NDJSON)
```

## Security model

- AES-256-GCM encrypted log, HKDF-derived key from machine ID
- SHA-256 hash-chained entries — any tampering breaks the chain
- Role-based API: every Bearer token is bound to a role
- Actor name in audit logs comes from the token, not user-supplied input
- Legal holds are hard-blocked in code — not just policy
- Dashboard served on `127.0.0.1` only

## Environment variables

| Variable | Purpose |
|----------|---------|
| `SLATE_DIR` | Override data directory (default: `~/.slate`) |
| `SLATE_SIGN_KEY` | Ed25519 private key hex for signing exports |
| `SLATE_NODE_KEY` | Ed25519 private key hex for node identity (peer transfers) |

## Build from source

Requires Go 1.22+.

```bash
go build ./...
go test ./...
```

## License

MIT. See `LICENSE`.
