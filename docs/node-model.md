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

Each node runs its own SLATE instance with its own machine-ID-derived encryption key. Logs are independent — a log from node-A cannot be decrypted on node-B.

Transfers between nodes are recorded on the sending node. The receiving node records a corresponding intake or transfer event.

For a complete cross-node custody chain: generate export bundles from all involved nodes and present them together.

## Node ID stability

Node IDs appear in every custody event. Change a node ID after deployment and the chain shows a gap. Keep node IDs stable for the lifetime of the installation.

Recommended naming: `<department-code>-<location>-<sequence>`

Examples:
- `hpd-evidence-001`
- `hpd-lab-001`
- `hpd-court-001`

## Planned: central aggregation

A future SLATE version will support a central aggregation node that pulls encrypted logs from all nodes and provides a unified cross-node chain-of-custody view. This will use the Harborlight SGAIL remote sync protocol.
