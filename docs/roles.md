# SLATE — Roles and Permissions

## Roles

| Role | Who uses it |
|------|------------|
| `chief` | Department leadership — full access |
| `evidence_clerk` | Evidence room staff — daily operations |
| `tech_admin` | IT/system administrators — config and audit, no evidence mutation |
| `officer` | Field officers — intake only |
| `auditor` | Internal or external reviewers — read-only |

## Permission matrix

| Permission | Chief | Evidence Clerk | Tech Admin | Officer | Auditor |
|------------|:-----:|:--------------:|:----------:|:-------:|:-------:|
| `intake` | ✓ | ✓ | | ✓ | |
| `transfer` | ✓ | ✓ | | | |
| `hold:set` | ✓ | ✓ | | | |
| `hold:release` | ✓ | ✓ | | | |
| `export` | ✓ | | | | |
| `destroy` | ✓ | | | | |
| `audit:read` | ✓ | | ✓ | | ✓ |
| `node:admin` | ✓ | | ✓ | | |
| `status` | ✓ | ✓ | ✓ | ✓ | ✓ |

## Dashboard tab visibility

| Tab | Required permission |
|-----|---------------------|
| Chief | `status` |
| Evidence Room | `intake` |
| Tech / Admin | `node:admin` |
| Daily Logs | `audit:read` |
| Officer View | `status` |

## Token management

Tokens are created and managed with `slate token`:

```bash
slate token add --role evidence_clerk --name "Clerk Rivera"
slate token list
slate token revoke <full-token-hex>
```

Tokens are 32-byte (256-bit) cryptographically random hex strings. They cannot be recovered after creation — copy them at generation time.

Revoked tokens stop working immediately (the server reloads `tokens.json` on every request).

## RBAC implementation

Permissions are checked server-side in the `require(perm)` HTTP middleware — not just in the dashboard UI. A client that bypasses the UI still receives 403 Forbidden for unauthorized operations.

The actor name recorded in every audit log event is the name from the token entry, not a user-supplied field. This ensures every log entry is cryptographically traceable to a specific token and role.
