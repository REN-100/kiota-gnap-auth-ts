# Contributing to kiota-gnap-auth-ts

Thank you for your interest in contributing to the Kiota GNAP Authentication Provider! This project is part of the [ShujaaPay](https://www.shujaapay.me) GNAP Stack, contributing open-source tooling to the [Open Payments](https://openpayments.dev) ecosystem.

## Getting Started

### Prerequisites

- **Node.js** >= 18.0.0
- **npm** >= 9
- **Git**

### Setup

```bash
# Clone the repo
git clone https://github.com/REN-100/kiota-gnap-auth-ts.git
cd kiota-gnap-auth-ts

# Also clone the signing library (peer dependency)
git clone https://github.com/REN-100/http-message-signatures-ts.git ../http-message-signatures-ts
cd ../http-message-signatures-ts && npm install && npm run build && cd ../kiota-gnap-auth-ts

# Install dependencies
npm install

# Run tests
npm test

# Type-check
npx tsc --noEmit
```

## Development Workflow

1. **Branch** from `main` using descriptive names: `feat/wallet-address-support`, `fix/token-rotation-race`
2. **Write tests first** — every new feature or fix should have accompanying tests
3. **Run the full suite** before submitting: `npm test && npx tsc --noEmit`
4. **Keep commits focused** — one logical change per commit

## Project Structure

```
src/
  index.ts                        # Public exports
  gnap-auth-provider.ts           # Kiota AuthenticationProvider
  gnap-access-token-provider.ts   # Token lifecycle orchestration
  gnap-grant-manager.ts           # GNAP grant lifecycle (RFC 9635)
  token-store.ts                  # In-memory token storage
  interaction-hash.ts             # Interaction hash verification (RFC 9635 §4.2.3)
  types.ts                        # TypeScript interfaces
tests/
  *.test.ts                       # Jest test files
```

## Key Design Decisions

- **Zero runtime dependencies** beyond Kiota abstractions and the signing library
- **Framework-agnostic** — works with any HTTP client or framework
- **Kiota-native** — follows Kiota patterns (`AuthenticationProvider`, `AllowedHostsValidator`)
- **RFC-first** — every feature maps to a specific RFC section

## Areas for Contribution

- **Persistent token stores** — Redis, SQLite, or PostgreSQL-backed `TokenStore` implementations
- **Integration tests** — end-to-end tests with [Rafiki](https://github.com/interledger/rafiki) testnet
- **ECDSA key proofs** — P-256 and P-384 key proof support
- **Interaction handlers** — Redirect flow utilities and user_code polling
- **Browser support** — WebCrypto API integration for browser-based clients

## Code Style

- TypeScript strict mode
- 2-space indentation
- JSDoc on all public APIs
- Descriptive variable names (no abbreviations)

## Submitting Changes

1. Open an issue to discuss significant changes before starting work
2. Fork and create a feature branch
3. Submit a Pull Request with a clear description
4. Ensure CI passes (type-check + tests + build)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

<p align="center">
  <a href="https://www.shujaapay.me">ShujaaPay</a> · Contributing to Open Payments
</p>
