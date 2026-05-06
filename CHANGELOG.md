# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-05-06

### Added
- **Token introspection** (`introspectToken()`) — RFC 9635 §6.3 compliance
- **Wallet address resolution** (`resolveWalletAddress()`) — Auto-discover auth/resource servers from Open Payments wallet addresses
- **Full rotation response** — `rotateToken()` now returns `TokenAccessResponse` with `value`, `manage`, `expiresIn`, `flags`, `access`
- **Resource cleanup** — `close()` method and `Symbol.asyncDispose` for lifecycle management
- **`TokenAccessResponse` type** — Structured return type for rotation and introspection
- **Wallet address tests** — 10 tests covering resolution, `$`-format, HTTPS enforcement, and error paths
- **Introspection tests** — 4 tests covering GET introspection, flat response, fallback, and error handling

### Changed
- `rotateToken()` return type changed from `string` to `TokenAccessResponse` (**BREAKING**)
- `TokenInfo.access` is now optional (supports metadata-only tokens)
- `interaction-hash.ts` uses static `import` from `crypto` instead of dynamic `require`

### Fixed
- Rotation logic in `GnapAccessTokenProvider` now persists new management URI, expiry, access, and flags from rotation response

## [0.1.0] - 2026-04-28

### Added
- Initial release
- Kiota `AuthenticationProvider` implementation with `AllowedHostsValidator`
- GNAP grant lifecycle: `requestGrant()`, `continueGrant()`, `rotateToken()`, `revokeToken()`, `deleteGrant()`
- HTTP Message Signatures (RFC 9421) via `@shujaapay/http-message-signatures`
- Content-Digest header generation (RFC 9530)
- Interaction hash verification (RFC 9635 §4.2.3) with timing-safe comparison
- Structured error handling (`GnapError`, `GnapInteractionRequiredError`)
- Token store with TTL-based expiration and auto-prune
- Proactive token refresh within grace period
- Concurrent acquisition guard (deduplication)
- Continuation polling with `too_fast` backoff
- Configurable retry with exponential backoff
- Lifecycle events: `token:acquired`, `token:rotated`, `token:rotation_failed`, `grant:interaction_required`
- Ed25519 and ECDSA-P256 key proof support
- Token flags (`bearer`, `durable`)
- Open Payments: `identifier`, `limits` (debitAmount/receiveAmount/interval), wallet address, client display
- CI pipeline with Node.js 18/20/22 matrix
