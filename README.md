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
slate intake     --case C --desc D [--cat CATEGORY] [--node NODE]
slate transfer   --item ID --from NODE --to NODE [--notes TEXT]
slate hold set   --item ID --reason TEXT
slate hold release --item ID
slate export     --case C [--sign]
slate token add  --role ROLE --name NAME
slate token list
slate token revoke TOKEN
slate keygen
slate serve      [--port 8890]
slate version
```

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

## Build from source

Requires Go 1.22+.

```bash
go build ./...
go test ./...
```

## License

MIT. See `LICENSE`.
