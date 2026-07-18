# SLATE — Node Model

## What is a node?

A **node** is a named SLATE installation at a physical or logical location:

- `evidence-room-1` — primary evidence room terminal
- `forensics-lab` — processing station
- `court-liaison` — transfer point for court submissions
- `archive-storage` — cold storage location

Set at init: `slate init --node <id>`

## Single-node (standard)

One SLATE instance, one encrypted log, one set of tokens. All custody events are recorded locally. This is the recommended starting configuration.

## Multi-node

Each node runs its own SLATE instance with its own machine-ID-derived encryption key. Logs are independent — a log from node-A cannot be decrypted on node-B. Because logs are non-portable by design, cross-node custody is **not** a merged log; it is stitched together by signed transfer bundles.

Transfers between nodes are recorded on the sending node. The receiving node records a corresponding transfer event that cites the same bundle ID.

For a complete cross-node custody chain: generate export bundles from all involved nodes and present them together.

## Multi-node LAN custody transfer (v1.1)

v1.1 adds direct, offline custody handoff between peer nodes on a department LAN.

### Transport: signed bundles over HTTP (not mTLS)

A handoff is an Ed25519-**signed transfer bundle** POSTed to the peer. We chose
signed bundles over mutual TLS because: there is no CA/PKI to run on a department
LAN; the signature secures the *evidence itself* (tamper-evident at rest, not just
in transit); and it reuses SLATE's existing Ed25519 trust anchor. mTLS would only
secure the pipe and would add certificate lifecycle management.

### Trust model

- **Node identity.** Each node has an Ed25519 identity keypair. The private key
  lives **only** in the `SLATE_NODE_KEY` environment variable and is never written
  to disk — matching SLATE's posture for export signing keys. Generate one with
  `slate peer keygen`; view your public identity with `slate peer identity`.
- **Enrollment (manual pairing only).** Operators exchange public keys out of
  band and enroll each peer by hand:
  `slate peer add --node ID --pubkey HEX --addr HOST:PORT`. Enrolled peers live in
  `~/.slate/peers.json` (public keys and addresses only — no secrets).
- **The receive listener is opt-in and explicit.** It is started with
  `slate serve --peer-listen HOST:PORT` and is the **only** part of SLATE that
  binds beyond `127.0.0.1`. The dashboard stays localhost-only. If `--peer-listen`
  is omitted, no inbound network surface exists.
- **Verification before acceptance.** On receipt the node looks up the enrolled
  public key for the *claimed sender* and verifies the bundle signature against
  **that** key (never the key the bundle asserts about itself). It also re-checks
  the bundle's events hash. Only then is the item stored — under its original ID,
  so the chain is continuous.
- **On failure, nothing is accepted.** An unenrolled sender, a bad signature, a
  mutated bundle, or a duplicate item ID (replay) is rejected with an error to the
  sender **and** a `WARN` `slate/peer_reject` event written to the receiver's
  audit log. Silence is never an acceptance.
- **Both sides record the handoff.** The sender logs `transfer` (out) and the
  receiver logs `transfer` (in), both citing the same `bundle_ref`. Legal holds
  block outbound transfer just as they block local transfer.

### Assumptions flagged

- The peer listener currently has **no transport encryption** — the bundle is
  signed but sent in cleartext over the LAN. Item metadata is therefore visible to
  a LAN eavesdropper. For a hostile network, front it with a VPN/WireGuard tunnel
  or add TLS in a later slice.
- Replay protection is limited to "refuse an item ID that already exists locally."
  A dedicated seen-bundle ledger is a candidate for a future slice.

## Node ID stability

Node IDs appear in every custody event. Change a node ID after deployment and the chain shows a gap. Keep node IDs stable for the lifetime of the installation.

Recommended naming: `<department-code>-<location>-<sequence>`

Examples:
- `hpd-evidence-001`
- `hpd-lab-001`
- `hpd-court-001`

## Planned: central aggregation

A future SLATE version will support a central aggregation node that pulls encrypted logs from all nodes and provides a unified cross-node chain-of-custody view. This will use the Harborlight SGAIL remote sync protocol. It will build on the v1.1 signed-bundle trust model above (auto-discovery and transport encryption are the next slices).
