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

## LAN auto-discovery (v1.2)

Manual pairing (v1.1) requires operators to hand-enter each peer's address, and
that address breaks whenever DHCP moves a node. v1.2 adds **opt-in discovery** that
removes the address-hunting friction **without weakening the trust model**.

### Discovery announces identity — it never grants trust

- A serving node can broadcast a **signed presence beacon** by adding `--announce`
  to `slate serve --peer-listen …`. The beacon is a small UDP multicast packet
  carrying the node ID, its Ed25519 public key, its peer-listen **port**, and a
  timestamp, **self-signed** with the node key. The host is deliberately *not* in
  the packet — the listener derives it from the UDP source address, so the beacon
  stays correct across DHCP changes.
- The signature proves the announcer holds the private key for the public key it
  advertises and makes the packet tamper-evident. An attacker on the LAN cannot
  forge a beacon for a public key they don't control.
- `slate peer discover` listens for beacons and prints who is out there, each with
  a **fingerprint** and a status (`new`, `enrolled`, `address-changed`,
  `key-mismatch`). It is strictly **read-only** — it never writes to `peers.json`.
- **Enrollment stays a deliberate, manual act.** After comparing a fingerprint out
  of band, the operator still runs `slate peer add …` to establish trust. Discovery
  cannot enroll a node, so a rogue node announcing itself gains nothing.

### The one safe auto-mutation: address refresh

`slate peer refresh` updates the **address** of peers that are *already enrolled*,
from their beacons. This is safe to automate because the update is applied only
when the beacon is signed by that peer's **enrolled public key** — forging it would
require the peer's private key. A beacon that claims an enrolled node's ID under a
**different** key is treated as a possible impersonation: it is **refused and
reported**, never applied. Use `--dry-run` to preview changes.

### Transport & posture

- Discovery uses **UDP multicast (group 239.255.42.99:8892 by default)** and the Go
  standard library only — no third-party mDNS/zeroconf dependency, consistent with
  SLATE's minimal-surface-area posture. Group and port are configurable.
- Discovery is **entirely opt-in**: without `--announce`, a node emits no beacons,
  and `discover`/`refresh` are inert commands that simply hear nothing.
- The beacon carries no evidence data — only presence and identity metadata.

## Node ID stability

Node IDs appear in every custody event. Change a node ID after deployment and the chain shows a gap. Keep node IDs stable for the lifetime of the installation.

Recommended naming: `<department-code>-<location>-<sequence>`

Examples:
- `hpd-evidence-001`
- `hpd-lab-001`
- `hpd-court-001`

## Planned: central aggregation

A future SLATE version will support a central aggregation node that pulls encrypted logs from all nodes and provides a unified cross-node chain-of-custody view. This will use the Harborlight SGAIL remote sync protocol. It will build on the v1.1 signed-bundle trust model and the v1.2 auto-discovery above (transport encryption is the remaining next slice).
