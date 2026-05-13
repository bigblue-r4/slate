# SLATE — Deployment Guide

## Requirements

- Go 1.22 or newer (build only — no runtime deps)
- Linux or macOS
- A machine you control in a physically secure location

## Install

```bash
git clone https://github.com/bigblue-r4/slate
cd slate
sudo bash install.sh --department "Honolulu PD" --node "node-001"
```

The installer builds the binary, copies it to `/usr/local/bin/slate`, installs the default soul file to `~/.slate/soul.toml`, and runs `slate init`.

## First-time token setup

```bash
# Add a chief token (full access)
slate token add --role chief --name "Chief Johnson"
# → prints a 64-hex-char token; copy it now — it cannot be recovered

# Add an evidence clerk token
slate token add --role evidence_clerk --name "Clerk Rivera"

# Add a read-only auditor token
slate token add --role auditor --name "Internal Audit"
```

## Start the dashboard

```bash
slate serve          # listens on 127.0.0.1:8890 by default
slate serve --port 8891
```

Open `http://127.0.0.1:8890` and enter a token at the login screen.

## View system status

```bash
slate status
```

## Verify log integrity

The audit log is SHA-256 hash-chained. Each entry contains `prev_hash` — the hash of the previous entry's plaintext. Any gap or modification breaks the chain.

Log is at: `~/.slate/primary/witness.log` (encrypted).

## Manage tokens

```bash
slate token list                    # show all tokens (partially masked)
slate token revoke <full-token>     # remove a token immediately
```

The server re-reads `tokens.json` on every request, so revoked tokens stop working immediately without restarting the server.

## Court export

```bash
slate export --case CASE-2026-0042
# Output: ~/.slate/exports/BUNDLE-YYYYMMDD-XXXXXXXX.ndjson
```

To sign exports:
```bash
slate keygen                          # generate key pair
export SLATE_SIGN_KEY=<private-key-hex>
slate export --case CASE-2026-0042 --sign
```

Store the public key in `~/.slate/config.json` under `signing_key_pub`.

## Multi-node deployment

Each node runs its own `slate` instance with its own encrypted log and key (derived from that machine's ID). Evidence transfers are logged independently on each node.

For court submissions involving multiple nodes:
1. Generate an export from each node's terminal
2. Combine the NDJSON files — each bundle has its own SHA-256 chain proof

Planned: central aggregation node for cross-node audit view.

## Backup

Back up `~/.slate/` regularly. The `primary/witness.log` is the authoritative audit trail. `primary/items.json` is the current item catalog (derived from the log, but faster to query).

The log is encrypted with an AES-256-GCM key derived from the machine ID. If you move the backup to a different machine, you will need the original machine's ID to decrypt it.

## Data directory override

```bash
export SLATE_DIR=/data/slate
slate init --department "HPD" --node "node-001"
slate serve
```

## Upgrading

```bash
git pull
go build -o slate ./cmd/slate
sudo install -m 0755 slate /usr/local/bin/slate
```

The log format is forward-compatible. The soul file and config are not modified by upgrades.

## Security checklist

- [ ] Soul file is `chmod 0400` — `ls -la ~/.slate/soul.toml`
- [ ] `tokens.json` is `chmod 0600` — `ls -la ~/.slate/tokens.json`
- [ ] Dashboard is not exposed beyond localhost without a TLS proxy
- [ ] At least one `chief` token exists; distribute other tokens only as needed
- [ ] Private signing key (`SLATE_SIGN_KEY`) is stored offline, not in config
- [ ] Audit log is backed up to a second location
